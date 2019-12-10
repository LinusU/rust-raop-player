// FIXME: eventually remove these
#![allow(non_snake_case, dead_code)]

// Docopt
#[macro_use]
extern crate serde_derive;
use docopt::Docopt;

// Standard dependencies
use std::marker::Unpin;
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

// General dependencies
use ctrlc;
use futures::future::{Abortable, AbortHandle};
use log::info;
use stderrlog;
use tokio::fs::File;
use futures::FutureExt;
use tokio::prelude::*;
use tokio::time::delay_for;

// Local dependencies
mod codec;
mod crypto;
mod curve25519;
mod keepalive_controller;
mod meta_data;
mod ntp;
mod raop_client;
mod rtp;
mod rtsp_client;
mod serialization;
mod sync_controller;
mod timing_controller;

use crate::codec::Codec;
use crate::crypto::Crypto;
use crate::meta_data::MetaDataItem;
use crate::ntp::NtpTime;
use crate::raop_client::{RaopClient, MAX_SAMPLES_PER_CHUNK};

const USAGE: &'static str = "
Usage:
    raop_play [options] <server-ip> <filename>
    raop_play (-h | --help)

Options:
    -a            Send ALAC compressed audio
    -d LEVEL      Debug level (0 = silent, 5 = trace) [default: 2]
    -e            Encrypt AirPlay stream using RSA
    -h, --help    Print this help and exit
    -l LATENCY    Latency in frames [default: 44100]
    -p PORT       Specify remote port [default: 5000]
    -v VOLUME     Specify volume between 0 and 100 [default: 50]
";

#[derive(Deserialize)]
struct Args {
    arg_server_ip: Ipv4Addr,
    arg_filename: String,
    flag_a: bool,
    flag_d: usize,
    flag_e: bool,
    flag_l: u32,
    flag_p: u16,
    flag_v: u8,
    flag_help: bool,
}

fn NTP2MS(ntp: u64) -> u64 { (((ntp >> 10) * 1000) >> 22) }
fn TS2NTP(ts: u32, rate: u32) -> u64 { ((((ts as u64) << 16) / (rate as u64)) << 16) }
fn TS2MS(ts: u32, rate: u32) -> u64 { NTP2MS(TS2NTP(ts,rate)) }

#[derive(PartialEq)]
enum Status {
    Stopped,
    Paused,
    Playing,
}

struct StatusLogger {
    abort_handle: AbortHandle,
}

impl StatusLogger {
    fn start(start: NtpTime, frames: Arc<Mutex<u64>>, latency: u32, sample_rate: u32) -> StatusLogger {
        let (abort_handle, abort_registration) = AbortHandle::new_pair();
        let future = StatusLogger::run(start, frames, latency, sample_rate);
        let future = Abortable::new(future, abort_registration).map(|_| {});
        tokio::spawn(future);
        StatusLogger { abort_handle }
    }

    fn stop(self) {
        self.abort_handle.abort();
    }

    async fn run(start: NtpTime, frames: Arc<Mutex<u64>>, latency: u32, sample_rate: u32) {
        loop {
            let now = NtpTime::now();

            let frames = *frames.lock().unwrap();

            if frames > 0 && frames > latency as u64 {
                info!("at {} ({} ms after start), played {} ms",
                    now, (now - start).as_millis(),
                    TS2MS((frames as u32) - latency, sample_rate));
            }

            delay_for(Duration::from_secs(1)).await;
        }
    }
}

async fn open_file(name: String) -> Box<dyn AsyncRead + Unpin> {
    if name == "-" {
        Box::new(tokio::io::stdin()) as Box<dyn AsyncRead + Unpin>
    } else {
        Box::new(File::open(name).await.unwrap()) as Box<dyn AsyncRead + Unpin>
    }
}

#[tokio::main(basic_scheduler)]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Args = Docopt::new(USAGE)
        .and_then(|d| d.deserialize())
        .unwrap_or_else(|e| e.exit());

    stderrlog::new().verbosity(args.flag_d).timestamp(stderrlog::Timestamp::Microsecond).color(stderrlog::ColorChoice::Never).init()?;

    let host = Ipv4Addr::UNSPECIFIED;
    let codec = Codec::new(args.flag_a, MAX_SAMPLES_PER_CHUNK, 44100, 16, 2);
    let crypto = Crypto::new(args.flag_e);
    let volume = RaopClient::float_volume(args.flag_v);
    let mut infile = open_file(args.arg_filename).await;

    let mut raopcl = RaopClient::connect(host, codec, args.flag_l, crypto, false, None, None, None, volume, args.arg_server_ip, args.flag_p, true).await?;

    let latency = raopcl.latency();

    info!("connected to {} on port {}, player latency is {} ms", args.arg_server_ip, args.flag_p, TS2MS(latency, raopcl.sample_rate()));

    let meta_data = MetaDataItem::listing_item(vec![
        MetaDataItem::item_kind(2),
    ]);

    raopcl.set_meta_data(meta_data).await?;

    let start = NtpTime::now();
    let status = Arc::new(Mutex::new(Status::Playing));

    let mut buf = [0; (MAX_SAMPLES_PER_CHUNK as usize) * 4];

    let frames = Arc::new(Mutex::new(0u64));
    let mut playtime: u64 = 0;

    {
        let status_handle = status.clone();
        ctrlc::set_handler(move || {
            info!("Recevied SIGINT, stopping playback");
            *status_handle.lock().unwrap() = Status::Stopped;
        })?;
    }

    let status_logger = StatusLogger::start(start, Arc::clone(&frames), raopcl.latency(), raopcl.sample_rate());

    loop {
        if *status.lock().unwrap() == Status::Playing {
            let n = infile.read(&mut buf).await?;
            if n == 0 { break }
            raopcl.accept_frames().await?;
            raopcl.send_chunk(&buf[0..n], &mut playtime).await?;
            *frames.lock().unwrap() += (n / 4) as u64;
        }

        if *status.lock().unwrap() == Status::Stopped {
            raopcl.stop().await;
            break
        }

        if !raopcl.is_playing().await { break }
    }

    status_logger.stop();
    raopcl.teardown().await
}
