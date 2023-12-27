// Docopt
#[macro_use]
extern crate serde_derive;
use async_executor::{Task, LocalExecutor};
use docopt::Docopt;

// Standard dependencies
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

// General dependencies
use async_fs::File;
use async_io::Timer;
use beefeater::{AddAssign, Beefeater};
use ctrlc;
use futures_lite::AsyncReadExt;
use log::{debug, info, warn};
use stderrlog;

// Local dependencies
use raop_play::{Codec, Crypto, Frames, MetaDataItem, NtpTime, RaopClient, MAX_SAMPLES_PER_CHUNK, RaopParams, SampleRate, Volume};

const USAGE: &str = "
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
    -v VOLUME     Specify volume between 0 and 100
";

#[derive(Deserialize)]
struct Args {
    arg_server_ip: IpAddr,
    arg_filename: String,
    flag_a: bool,
    flag_d: usize,
    flag_e: bool,
    flag_l: u64,
    flag_p: u16,
    flag_v: Option<u8>,
}

#[derive(Clone, Copy, PartialEq)]
enum Status {
    Stopped,
    Playing,
}

struct StatusLogger {
    task: Task<()>,
}

impl StatusLogger {
    fn start(executor: &LocalExecutor, start: NtpTime, frames: Arc<Beefeater<Frames>>, latency: Frames, sample_rate: SampleRate) -> StatusLogger {
        let future = StatusLogger::run(start, frames, latency, sample_rate);
        StatusLogger { task: executor.spawn(future) }
    }

    async fn stop(self) {
        self.task.cancel().await;
    }

    async fn run(start: NtpTime, frames: Arc<Beefeater<Frames>>, latency: Frames, sample_rate: SampleRate) {
        loop {
            let now = NtpTime::now();
            let frames = frames.load();

            if frames > latency {
                debug!("at {} ({} ms after start), played {} ms", now, (now - start).as_millis(), ((frames - latency) / sample_rate).as_millis());
            }

            Timer::after(Duration::from_secs(1)).await;
        }
    }
}

async fn open_file(name: String) -> std::io::Result<File> {
    if name == "-" {
        File::open("/dev/stdin").await
    } else {
        File::open(name).await
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let executor = LocalExecutor::new();
    let future = main_(&executor);

    futures_lite::future::block_on(executor.run(future))
}

async fn main_(executor: &LocalExecutor<'_>) -> Result<(), Box<dyn std::error::Error>> {
    let args: Args = Docopt::new(USAGE)
        .and_then(|d| d.deserialize())
        .unwrap_or_else(|e| e.exit());

    stderrlog::new().verbosity(args.flag_d).timestamp(stderrlog::Timestamp::Microsecond).color(stderrlog::ColorChoice::Never).init()?;

    let mut params = RaopParams::new();

    params.set_codec(Codec::new(args.flag_a, MAX_SAMPLES_PER_CHUNK, SampleRate::Hz44100, 16, 2));
    params.set_desired_latency(Frames::new(args.flag_l));
    params.set_crypto(Crypto::new(args.flag_e));

    let remote = SocketAddr::new(args.arg_server_ip, args.flag_p);
    let mut infile = open_file(args.arg_filename).await?;

    let mut raopcl = RaopClient::connect(&executor, params, remote).await?;

    if let Some(volume) = args.flag_v {
        raopcl.set_volume(Volume::from_percent(volume)).await?;
    }

    let latency = raopcl.latency();

    info!("connected to {} on port {}, player latency is {} ms", args.arg_server_ip, args.flag_p, (latency / raopcl.sample_rate()).as_millis());

    let meta_data = MetaDataItem::listing_item(vec![
        MetaDataItem::item_kind(2),
    ]);

    if let Err(err) = raopcl.set_meta_data(meta_data).await {
        warn!("Failed to set meta data: {}", err);
    }

    let start = NtpTime::now();
    let status = Arc::new(Beefeater::new(Status::Playing));

    let mut buf = [0; MAX_SAMPLES_PER_CHUNK.as_usize(4)];

    let frames = Arc::new(Beefeater::new(Frames::new(0)));

    {
        let status = status.clone();
        ctrlc::set_handler(move || {
            info!("Recevied SIGINT, stopping playback");
            status.store(Status::Stopped);
        })?;
    }

    let status_logger = StatusLogger::start(&executor, start, Arc::clone(&frames), raopcl.latency(), raopcl.sample_rate());

    loop {
        match status.load() {
            Status::Playing => {
                let n = infile.read(&mut buf).await?;
                if n == 0 { break }
                raopcl.accept_frames().await?;
                raopcl.send_chunk(&buf[0..n]).await?;
                frames.add_assign(Frames::from_usize(n, 4));
            }
            Status::Stopped => {
                break;
            }
        }
    }

    status_logger.stop().await;
    raopcl.teardown().await
}
