// FIXME: eventually remove these
#![allow(non_snake_case, non_camel_case_types, non_upper_case_globals, dead_code)]

// Link in the C part of the program
#[link(name="raop", kind="static")]
mod bindings;

// Docopt
#[macro_use]
extern crate serde_derive;
use docopt::Docopt;

// Standard dependencies
use std::fs::File;
use std::io;
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

// General dependencies
use ctrlc;
use log::info;
use stderrlog;

// Local dependencies
mod codec;
mod crypto;
mod ntp;
mod raop_client;
mod rtp;
mod rtsp_client;
mod serialization;

use crate::codec::Codec;
use crate::crypto::Crypto;
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

fn open_file(name: String) -> Box<dyn io::Read> {
    if name == "-" {
        Box::new(io::stdin())
    } else {
        Box::new(File::open(name).unwrap())
    }
}

fn main() -> Result<(), Box<std::error::Error>> {
    let args: Args = Docopt::new(USAGE)
        .and_then(|d| d.deserialize())
        .unwrap_or_else(|e| e.exit());

    stderrlog::new().verbosity(args.flag_d).timestamp(stderrlog::Timestamp::Microsecond).color(stderrlog::ColorChoice::Never).init().unwrap();

    let host = Ipv4Addr::UNSPECIFIED;
    let codec = Codec::new(args.flag_a, MAX_SAMPLES_PER_CHUNK, 44100, 16, 2);
    let crypto = Crypto::new(args.flag_e);
    let volume = RaopClient::float_volume(args.flag_v);
    let mut infile = open_file(args.arg_filename);

    let mut raopcl = RaopClient::connect(host, codec, args.flag_l, crypto, false, None, None, None, volume, args.arg_server_ip, args.flag_p, true).unwrap();

    let latency = raopcl.latency();

    info!("connected to {} on port {}, player latency is {} ms", args.arg_server_ip, args.flag_p, TS2MS(latency, raopcl.sample_rate()));

    let start = NtpTime::now();
    let status = Arc::new(Mutex::new(Status::Playing));

    let mut buf = [0; (MAX_SAMPLES_PER_CHUNK as usize) * 4];

    let mut last = NtpTime::ZERO;
    let mut frames: u64 = 0;
    let mut playtime: u64 = 0;

    {
        let status_handle = status.clone();
        ctrlc::set_handler(move || {
            info!("Recevied SIGINT, stopping playback");
            *status_handle.lock().unwrap() = Status::Stopped;
        }).unwrap();
    }

    loop {
        let now = NtpTime::now();

        if (now - last) > Duration::from_secs(1) {
            last = now;

            if frames > 0 && frames > raopcl.latency().into() {
                info!("at {} ({} ms after start), played {} ms",
                    now, (now - start).as_millis(),
                    TS2MS((frames as u32) - raopcl.latency(), raopcl.sample_rate()));
            }
        }

        if *status.lock().unwrap() == Status::Playing && raopcl.accept_frames()? {
            let n = infile.read(&mut buf).unwrap();
            if n == 0 { break }
            raopcl.send_chunk(&buf[0..n], &mut playtime)?;
            frames += (n / 4) as u64;
        }

        if *status.lock().unwrap() == Status::Stopped {
            raopcl.stop();
            break
        }

        if !raopcl.is_playing() { break }
    }

    Ok(())
}
