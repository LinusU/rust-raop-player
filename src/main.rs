// FIXME: eventually remove these
#![allow(non_snake_case, non_camel_case_types, non_upper_case_globals, dead_code)]

// Required for linking towards openssl
use openssl_sys;

// Link in the C part of the program
#[link(name="raop", kind="static")]
mod bindings;
use crate::bindings::*;
use std::ptr;

// Docopt
#[macro_use]
extern crate serde_derive;
use docopt::Docopt;

// General dependencies
use std::net::Ipv4Addr;
use stderrlog;
use log::info;
use std::io;
use std::fs::File;

// Local dependencies
mod alac_encoder;
mod raop_client;
mod rtsp_client;
use crate::raop_client::{Codec, Crypto, RaopClient};

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

impl From<Ipv4Addr> for in_addr {
    fn from(ip: Ipv4Addr) -> in_addr {
        in_addr { s_addr: u32::from(ip).swap_bytes() }
    }
}

impl From<in_addr> for Ipv4Addr {
    fn from(ip: in_addr) -> Ipv4Addr {
        Ipv4Addr::from(ip.s_addr.swap_bytes())
    }
}

fn NTP2MS(ntp: u64) -> u64 { (((ntp >> 10) * 1000) >> 22) }
fn MS2NTP(ms: u64) -> u64 { (((ms << 22) / 1000) << 10) }
// #define TIME_MS2NTP(time) raopcl_time32_to_ntp(time)
fn TS2NTP(ts: u32, rate: u32) -> u64 { ((((ts as u64) << 16) / (rate as u64)) << 16) }
// #define MS2TS(ms, rate) ((((u64_t) (ms)) * (rate)) / 1000)
fn TS2MS(ts: u32, rate: u32) -> u64 { NTP2MS(TS2NTP(ts,rate)) }

fn SEC(ntp: u64) -> u32 { (ntp >> 32) as u32 }
fn FRAC(ntp: u64) -> u32 { ntp as u32 }
// #define SECNTP(ntp) SEC(ntp),FRAC(ntp)
// #define MSEC(ntp)  ((u32_t) ((((ntp) >> 16)*1000) >> 16))

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
    let codec = if args.flag_a { Codec::ALAC } else { Codec::PCM };
    let crypto = if args.flag_e { Crypto::RSA } else { Crypto::Clear };
    let volume = RaopClient::float_volume(args.flag_v);
    let mut infile = open_file(args.arg_filename);

    let mut raopcl = RaopClient::new(host, codec, MAX_SAMPLES_PER_CHUNK, args.flag_l, crypto, false, None, None, None, 44100, 16, 2, volume, args.arg_server_ip, args.flag_p).unwrap();

    unsafe {
        raopcl.connect(true)?;

        let latency = raopcl.latency();

        info!("connected to {} on port {}, player latency is {} ms", args.arg_server_ip, args.flag_p, TS2MS(latency, raopcl.sample_rate()));

        let start = get_ntp(ptr::null_mut());
        let mut status = Status::Playing;

        let mut buf = [0; (MAX_SAMPLES_PER_CHUNK as usize) * 4];

        let mut last: u64 = 0;
        let mut frames: u64 = 0;
        let mut playtime: u64 = 0;

        loop {
            let now = get_ntp(ptr::null_mut());

            if (now - last) > MS2NTP(1000) {
                last = now;

                if frames > 0 && frames > raopcl.latency().into() {
                    info!("at {}.{} ({} ms after start), played {} ms",
                        SEC(now), FRAC(now), NTP2MS(now - start),
                        TS2MS((frames as u32) - raopcl.latency(), raopcl.sample_rate()));
                }
            }

            if status == Status::Playing && raopcl.accept_frames()? {
                let n = infile.read(&mut buf).unwrap();
                raopcl.send_chunk(&mut buf, n / 4, &mut playtime)?;
                frames += (n / 4) as u64;
            }

            if !raopcl.is_playing() { break }
        }

        raopcl.disconnect()?;
    }

    Ok(())
}
