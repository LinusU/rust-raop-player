use crate::codec::Codec;
use crate::crypto::Crypto;
use crate::frames::Frames;
use crate::keepalive_controller::KeepaliveController;
use crate::meta_data::MetaDataItem;
use crate::ntp::NtpTime;
use crate::rtp::{RtpHeader, RtpAudioPacket};
use crate::rtsp_client::RTSPClient;
use crate::sample_rate::SampleRate;
use crate::serialization::{Serializable};
use crate::sync_controller::SyncController;
use crate::timing_controller::TimingController;
use crate::volume::Volume;

use std::net::{Ipv4Addr, IpAddr};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use rand::random;
use log::{error, info, debug, trace};
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tokio::time::delay_for;

const LATENCY_MIN: Frames = Frames::new(11025);

pub const MAX_BACKLOG: u16 = 512;
pub const MAX_SAMPLES_PER_CHUNK: Frames = Frames::new(352);

pub fn analyse_setup(setup_headers: Vec<(String, String)>) -> Result<(u16, u16, u16), Box<dyn std::error::Error>> {
    // get transport (port ...) info
    let transport_header = setup_headers.iter().find(|header| header.0.to_lowercase() == "transport").map(|header| header.1.as_str());

    if transport_header.is_none() {
        error!("no transport in response");
        panic!("no transport in response");
    }

    let mut audio_port: u16 = 0;
    let mut ctrl_port: u16 = 0;
    let mut time_port: u16 = 0;

    for token in transport_header.unwrap().split(';') {
        match token.split('=').collect::<Vec<&str>>().as_slice() {
            ["server_port", port] => audio_port = port.parse()?,
            ["control_port", port] => ctrl_port = port.parse()?,
            ["timing_port", port] => time_port = port.parse()?,
            _ => {},
        }
    }

    if audio_port == 0 || ctrl_port == 0 {
        error!("missing a RTP port in response");
        panic!("missing a RTP port in response");
    }

    if time_port == 0 {
        info!("missing timing port, will get it later");
    }

    Ok((audio_port, ctrl_port, time_port))
}

#[derive(PartialEq, PartialOrd)]
enum RaopState {
    Flushing,
    Streaming,
}

#[derive(Clone, Copy, PartialEq)]
struct MetaDataCapabilities {
    text: bool,
    artwork: bool,
    progress: bool,
}

impl FromStr for MetaDataCapabilities {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(MetaDataCapabilities {
            text: s.contains('0'),
            artwork: s.contains('1'),
            progress: s.contains('2'),
        })
    }
}

pub struct BacklogEntry {
    pub seq_number: u16,
    pub timestamp: Frames,
    pub packet: RtpAudioPacket,
}

pub struct Status {
    state: RaopState,
    seq_number: u16,
    pub head_ts: Frames,
    pause_ts: Frames,
    start_ts: Frames,
    first_ts: Frames,
    first_pkt: bool,
    pub backlog: [Option<BacklogEntry>; 512usize],
}

pub struct SaneAudio {
    pub avail: u64,
    pub select: u64,
    pub send: u64,
}

pub struct Sane {
    pub ctrl: u64,
    pub time: u64,
    pub audio: SaneAudio,
}

impl Sane {
    fn new() -> Sane {
        Sane {
            ctrl: 0,
            time: 0,
            audio: SaneAudio { avail: 0, select: 0, send: 0 },
        }
    }
}

pub struct RaopClient {
    // Immutable properties
    remote_addr: IpAddr,
    local_addr: IpAddr,
    rtsp_port: u16,

    auth: bool,

    codec: Codec,
    crypto: Crypto,
    meta_data_capabilities: MetaDataCapabilities,

    secret: Option<String>,
    et: Option<String>,

    latency: Frames,

    // Mutable properties
    keepalive_controller: KeepaliveController,
    rtp_audio: Arc<Mutex<UdpSocket>>,
    sync_controller: SyncController,
    timing_controller: TimingController,

    sane: Arc<Mutex<Sane>>,
    retransmit: Arc<Mutex<u32>>,

    ssrc: Arc<Mutex<u32>>,

    status: Arc<Mutex<Status>>,

    volume: Arc<Mutex<Option<Volume>>>,

    rtsp_client: Arc<Mutex<RTSPClient>>,
}

impl RaopClient {
    pub async fn connect(local_addr_ipv4: Ipv4Addr, codec: Codec, desired_latency: Frames, crypto: Crypto, auth: bool, secret: Option<&str>, et: Option<&str>, md: Option<&str>, remote_addr_ipv4: Ipv4Addr, rtsp_port: u16) -> Result<RaopClient, Box<dyn std::error::Error>> {
        if codec.chunk_length() > MAX_SAMPLES_PER_CHUNK {
            panic!("Chunk length must below {}", MAX_SAMPLES_PER_CHUNK);
        }

        let local_addr: IpAddr = local_addr_ipv4.into();
        let remote_addr: IpAddr = remote_addr_ipv4.into();

        let secret = secret.map(|s| s.to_owned());
        let et = et.map(|s| s.to_owned());
        let mut latency = std::cmp::max(desired_latency, LATENCY_MIN);

        // strcpy(raopcld->DACP_id, DACP_id ? DACP_id : "");
        // strcpy(raopcld->active_remote, active_remote ? active_remote : "");

        let meta_data_capabilities = md.unwrap_or("").parse::<MetaDataCapabilities>().unwrap();

        info!("using {} coding", codec);

        let retransmit_mutex = Arc::new(Mutex::new(0));
        let sane_mutex = Arc::new(Mutex::new(Sane::new()));

        let sid = format!("{:010}", random::<u32>());
        let sci = format!("{:016x}", random::<u64>());

        // RTSP misc setup
        let mut rtsp_client = RTSPClient::connect((remote_addr, rtsp_port), &sid, "iTunes/7.6.2 (Windows; N;)", &[("Client-Instance", &sci)]).await?;
        // FIXME:
        // if self.DACP_id[0] != 0 { rtspcl_add_eself.((*s_elient..cnew("DACP-ID").unwrap().into_raw(), self.DACP_id); }
        // if self.active_remote[0] != 0 { rtspclself.esel.f_ient((.s_elient.new("Active-Remote").unwrap().into_raw(), self.active_remote)?;

        info!("local interface {}", rtsp_client.local_ip()?);

        // RTSP pairing verify for AppleTV
        if let Some(ref secret) = secret {
            rtsp_client.pair_verify(secret).await?;
        }

        // Send pubkey for MFi devices
        if et.as_ref().map(|et| et.contains('4')).unwrap_or(false) {
            rtsp_client.auth_setup().await?;
        }

        let mut sdp = format!(
            "v=0\r\no=iTunes {} 0 IN IP4 {}\r\ns=iTunes\r\nc=IN IP4 {}\r\nt=0 0\r\n",
            sid,
            rtsp_client.local_ip()?,
            remote_addr,
        );

        sdp.push_str(codec.sdp().as_str());
        sdp.push_str(crypto.sdp().as_str());

        // AppleTV expects now the timing port ot be opened BEFORE the setup message
        let rtp_time = UdpSocket::bind((local_addr, 0)).await?;
        let local_time_port = rtp_time.local_addr()?.port();
        let timing_controller = TimingController::start(rtp_time);

        // RTSP ANNOUNCE
        if auth && !crypto.is_clear() {
            panic!("Not implemented");
            // let seed_sac: [u8; 16] = random();
            // base64_encode(&seed.sac, 16, &sac);
            // remove_char_from_string(sac, '=');
            // rtsp_client.add_exthds("Apple-Challenge", &sac)?;
            // rtsp_client.announce_sdp(&sdp)?;
            // rtsp_client.mark_del_exthds("Apple-Challenge")?;
        } else {
            rtsp_client.announce_sdp(&sdp).await?;
        }

        // open RTP sockets, need local ports here before sending SETUP
        let rtp_ctrl = UdpSocket::bind((local_addr, 0)).await?;
        let local_ctrl_port = rtp_ctrl.local_addr()?.port();

        let rtp_audio = UdpSocket::bind((local_addr, 0)).await?;
        let local_audio_port = rtp_audio.local_addr()?.port();

        // RTSP SETUP : get all RTP destination ports
        let setup_headers = rtsp_client.setup(local_ctrl_port, local_time_port).await?;
        let (remote_audio_port, remote_ctrl_port, remote_time_port) = analyse_setup(setup_headers)?;

        debug!("opened audio socket   l:{:05} r:{}", local_audio_port, remote_audio_port);
        debug!("opened timing socket  l:{:05} r:{}", local_time_port, remote_time_port);
        debug!("opened control socket l:{:05} r:{}", local_ctrl_port, remote_ctrl_port);

        rtp_audio.connect((remote_addr, remote_audio_port)).await?;
        rtp_ctrl.connect((remote_addr, remote_ctrl_port)).await?;

        let rtp_audio_mutex = Arc::new(Mutex::new(rtp_audio));

        let status = Status {
            state: RaopState::Flushing,
            seq_number: random(),
            head_ts: Frames::new(0),
            pause_ts: Frames::new(0),
            start_ts: Frames::new(0),
            first_ts: Frames::new(0),
            first_pkt: true,
            // FIXME: https://github.com/rust-lang/rust/issues/49147
            backlog: [
                None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None,
                None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None,
                None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None,
                None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None,
                None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None,
                None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None,
                None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None,
                None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None,
                None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None,
                None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None,
                None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None,
                None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None,
                None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None,
                None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None,
                None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None,
                None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None,
            ],
        };

        let record_headers = rtsp_client.record(status.seq_number + 1, NtpTime::now().into_timestamp(codec.sample_rate())).await?;
        let returned_latency = record_headers.iter().find(|header| header.0.to_lowercase() == "audio-latency").map(|header| header.1.as_str());

        if let Some(returned_latency) = returned_latency {
            latency = std::cmp::max(latency, returned_latency.parse()?);
        }

        let status_mutex = Arc::new(Mutex::new(status));

        let sync_controller = {
            let status_ref = Arc::clone(&status_mutex);
            let sane_ref = Arc::clone(&sane_mutex);
            let retransmit_ref = Arc::clone(&retransmit_mutex);
            let sample_rate = codec.sample_rate();

            SyncController::start(rtp_ctrl, status_ref, sane_ref, retransmit_ref, latency, sample_rate)
        };

        let rtsp_client_mutex = Arc::new(Mutex::new(rtsp_client));
        let keepalive_controller = KeepaliveController::start(Arc::clone(&rtsp_client_mutex));

        Ok(RaopClient {
            // Immutable properties
            remote_addr,
            local_addr,
            rtsp_port,
            auth,
            codec,
            crypto,
            meta_data_capabilities,
            secret,
            et,

            // Mutable properties
            keepalive_controller,
            rtp_audio: rtp_audio_mutex,
            sync_controller,
            timing_controller,

            sane: sane_mutex,

            retransmit: retransmit_mutex,
            ssrc: Arc::new(Mutex::new(random())),

            status: status_mutex,

            latency,
            volume: Arc::new(Mutex::new(None)),

            rtsp_client: rtsp_client_mutex,
        })
    }

    pub fn latency(&self) -> Frames {
        // Why do AirPlay devices use required latency + 11025?
        self.latency + LATENCY_MIN
    }

    pub fn sample_rate(&self) -> SampleRate {
        self.codec.sample_rate()
    }

    async fn flush(&self, mut status: &mut Status) -> Result<(), Box<dyn std::error::Error>> {
        let now = NtpTime::now();
        let now_ts = now.into_timestamp(self.codec.sample_rate());

        // We are either paused or we shouldn't start until later
        if status.pause_ts != Frames::new(0) || status.start_ts > now_ts + self.latency() {
            unimplemented!();
        }

        info!("begining to stream hts:{} n:{}", status.head_ts, now);
        status.state = RaopState::Streaming;

        // unpausing ...
        if status.pause_ts == Frames::new(0) {
            status.head_ts = if status.start_ts > Frames::new(0) { status.start_ts } else { now_ts };
            status.first_ts = status.head_ts;

            self.sync_controller.send_sync(&mut status, self.codec.sample_rate(), self.latency, true).await?;

            info!("restarting w/o pause n:{}, hts:{}", now, status.head_ts);
        } else {
            let mut n: u16;
            let mut i: u16;
            let chunks = (u64::from(self.latency()) / u64::from(self.codec.chunk_length())) as u16;

            // if un-pausing w/o start_time, can anticipate as we have buffer
            status.first_ts = if status.start_ts > Frames::new(0) { status.start_ts } else { now_ts - self.latency() };

            // last head_ts shall be first + raopcl_latency - chunk_length
            status.head_ts = status.first_ts - self.codec.chunk_length();

            self.sync_controller.send_sync(&mut status, self.codec.sample_rate(), self.latency, true).await?;

            info!("restarting w/ pause n:{}, hts:{} (re-send: {})", now, status.head_ts, chunks);

            // search pause_ts in backlog, it should be backward, not too far
            n = status.seq_number;
            i = 0;
            while i < MAX_BACKLOG && status.backlog[(n % MAX_BACKLOG) as usize].as_ref().map(|e| e.timestamp).unwrap_or_else(|| Frames::new(0)) > status.pause_ts {
                i += 1;
                n -= 1;
            }

            // the resend shall go up to (including) pause_ts
            n = (n - chunks + 1) % MAX_BACKLOG;

            // re-send old packets
            i = 0;
            while i < chunks {
                let index = ((n + i) % MAX_BACKLOG) as usize;

                if let Some(mut entry) = status.backlog[index].take() {
                    status.seq_number += 1;

                    entry.packet.header.type_ = if status.first_pkt { 0xE0 } else { 0x60 };
                    entry.packet.header.seq = status.seq_number;
                    entry.packet.timestamp = status.head_ts;
                    status.first_pkt = false;

                    self._send_audio(&mut status, &entry.packet).await?;

                    // then replace packets in backlog in case
                    let reindex = (status.seq_number % MAX_BACKLOG) as usize;

                    status.backlog[reindex] = Some(BacklogEntry {
                        seq_number: status.seq_number,
                        timestamp: status.head_ts,
                        packet: entry.packet,
                    });

                    status.head_ts += self.codec.chunk_length();

                    i += 1;
                }
            }

            debug!("finished resend {}", i);
        }

        status.pause_ts = Frames::new(0);
        status.start_ts = Frames::new(0);

        Ok(())
    }

    pub async fn accept_frames(&self) -> Result<(), Box<dyn std::error::Error>> {
        trace!("[accept_frames] - aquiring status");
        let mut status = self.status.lock().await;
        trace!("[accept_frames] - got status");

        // a flushing is pending
        if status.state == RaopState::Flushing {
            self.flush(&mut status).await?;
        }

        // when paused, fix "now" at the time when it was paused.
        let now_ts = if status.pause_ts > Frames::new(0) {
            status.pause_ts
        } else {
            NtpTime::now().into_timestamp(self.codec.sample_rate())
        };

        let chunk_length = self.codec.chunk_length();
        let head_ts = status.head_ts;

        trace!("[accept_frames] - dropping status");
        drop(status);

        if now_ts < head_ts + chunk_length {
            let sleep_frames = (head_ts + chunk_length) - now_ts;
            let sleep_duration = sleep_frames / self.codec.sample_rate();
            delay_for(sleep_duration).await;
        }

        Ok(())
    }

    pub async fn send_chunk(&mut self, sample: &[u8], playtime: &mut Duration) -> Result<(), Box<dyn std::error::Error>> {
        let now = NtpTime::now();

        trace!("[send_chunk] - aquiring status");
        let mut status = self.status.lock().await;
        trace!("[send_chunk] - got status");

        let encoded = self.codec.encode_chunk(&sample);
        let encrypted = self.crypto.encrypt(encoded)?;

        *playtime = (status.head_ts + self.latency()) / self.codec.sample_rate();

        trace!("sending audio ts:{} (pt:{} now:{}) ", status.head_ts, playtime.as_secs_f32(), NtpTime::now());

        status.seq_number = status.seq_number.wrapping_add(1);

        let packet = RtpAudioPacket {
            header: RtpHeader {
                proto: 0x80,
                type_: (if status.first_pkt { 0xE0 } else { 0x60 }),
                seq: status.seq_number,
            },
            timestamp: status.head_ts,
            ssrc: (*self.ssrc.lock().await as u32),
            data: encrypted,
        };
        status.first_pkt = false;

        self._send_audio(&mut status, &packet).await?;

        let n = (status.seq_number % MAX_BACKLOG) as usize;

        status.backlog[n] = Some(BacklogEntry {
            seq_number: status.seq_number,
            timestamp: status.head_ts,
            packet,
        });

        status.head_ts += self.codec.chunk_length();

        // Print extra info every ten seconds
        if playtime.as_secs() % 10 == 0 && playtime.subsec_millis() < 8 {
            let sane = self.sane.lock().await;
            let retransmit = *self.retransmit.lock().await;
            info!("check n:{} p:{} ts:{} sn:{} retr:{} avail:{} send:{} select:{}",
                now.millis(), playtime.as_secs_f32(), status.head_ts, status.seq_number,
                retransmit, sane.audio.avail, sane.audio.send, sane.audio.select);
        }

        trace!("[send_chunk] - dropping status");

        Ok(())
    }

    pub async fn set_volume(&self, vol: Volume) -> Result<(), Box<dyn std::error::Error>> {
        *self.volume.lock().await = Some(vol);

        let parameter = format!("volume: {}\r\n", vol.into_f32());
        self.rtsp_client.lock().await.set_parameter(&parameter).await?;

        Ok(())
    }

    pub async fn set_meta_data(&self, meta_data: MetaDataItem) -> Result<(), Box<dyn std::error::Error>> {
        let ts = (*self.status.lock().await).head_ts;
        (*self.rtsp_client.lock().await).set_meta_data(ts, meta_data).await
    }

    pub async fn teardown(mut self) -> Result<(), Box<dyn std::error::Error>> {
        let status = self.status.lock().await;

        self.keepalive_controller.stop();
        self.sync_controller.stop();
        self.timing_controller.stop();

        let mut rtsp_client = self.rtsp_client.lock().await;
        rtsp_client.flush(status.seq_number + 1, status.head_ts + Frames::new(1)).await?;
        rtsp_client.teardown().await
    }

    async fn _send_audio(&self, status: &mut Status, packet: &RtpAudioPacket) -> Result<bool, Box<dyn std::error::Error>> {
        /*
        Do not send if audio port closed or we are not yet in streaming state. We
        might be just waiting for flush to happen in the case of a device taking a
        lot of time to connect, so avoid disturbing it with frames. Still, for sync
        reasons or when a starting time has been set, it's normal that the caller
        uses raopcld_accept_frames() and tries to send frames even before the
        connect has returned in case of multi-threaded application
        */
        // FIXME: if self.rtp_ports.audio.fd == -1  { return Ok(false); }
        if status.state != RaopState::Streaming { return Ok(false); }

        let mut socket = self.rtp_audio.lock().await;
        let n = socket.send(&packet.as_bytes()).await.unwrap();
        drop(socket);

        let mut ret = true;

        {
            let mut sane = self.sane.lock().await;

            if n != packet.size() {
                debug!("error sending audio packet");
                ret = false;
                sane.audio.send += 1;
            } else {
                sane.audio.send = 0;
            }
        }

        Ok(ret)
    }
}
