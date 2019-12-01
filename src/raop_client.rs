use crate::codec::Codec;
use crate::crypto::Crypto;
use crate::keepalive_controller::KeepaliveController;
use crate::meta_data::MetaDataItem;
use crate::ntp::NtpTime;
use crate::rtp::{RtpHeader, RtpAudioPacket};
use crate::rtsp_client::RTSPClient;
use crate::serialization::{Serializable};
use crate::sync_controller::SyncController;
use crate::timing_controller::TimingController;

use std::net::{Ipv4Addr, IpAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use rand::random;
use log::{error, info, debug, trace};
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tokio::time::delay_for;

const VOLUME_MIN: f32 = -30.0;
const VOLUME_MAX: f32 = 0.0;
const LATENCY_MIN: u32 = 11025;

pub const MAX_BACKLOG: u16 = 512;
pub const MAX_SAMPLES_PER_CHUNK: u32 = 352;

fn NTP2MS(ntp: u64) -> u64 { (((ntp >> 10) * 1000) >> 22) }
fn TS2NTP(ts: u64, rate: u32) -> u64 { ((((ts as u64) << 16) / (rate as u64)) << 16) }
fn NTP2TS(ntp: u64, rate: u32) -> u64 { (((ntp >> 16) * rate as u64) >> 16) }

fn SEC(ntp: u64) -> u32 { (ntp >> 32) as u32 }
fn FRAC(ntp: u64) -> u32 { ntp as u32 }
fn MSEC(ntp: u64) -> u32 { (((ntp >> 16) * 1000) >> 16) as u32 }

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
    Down,
    Flushing,
    Flushed,
    Streaming,
}

#[derive(Clone, Copy, PartialEq)]
struct MetaDataCapabilities {
    text: bool,
    artwork: bool,
    progress: bool,
}

pub struct BacklogEntry {
    pub seq_number: u16,
    pub timestamp: u64,
    pub packet: RtpAudioPacket,
}

pub struct Status {
    state: RaopState,
    seq_number: u16,
    pub head_ts: u64,
    pause_ts: u64,
    start_ts: u64,
    first_ts: u64,
    first_pkt: bool,
    flushing: bool,
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

    // Mutable properties
    keepalive_controller: KeepaliveController,
    rtp_audio: Arc<Mutex<UdpSocket>>,
    sync_controller: SyncController,
    timing_controller: TimingController,

    sane: Arc<Mutex<Sane>>,
    retransmit: Arc<Mutex<u32>>,

    ssrc: Arc<Mutex<u32>>,

    status: Arc<Mutex<Status>>,

    latency_frames: Arc<AtomicU32>,
    volume: Arc<Mutex<f32>>,

    rtsp_client: Arc<Mutex<RTSPClient>>,
}

impl RaopClient {
    pub async fn connect(local_addr_ipv4: Ipv4Addr, codec: Codec, latency_frames: u32, crypto: Crypto, auth: bool, secret: Option<&str>, et: Option<&str>, md: Option<&str>, volume: f32, remote_addr_ipv4: Ipv4Addr, rtsp_port: u16, set_volume: bool) -> Result<RaopClient, Box<dyn std::error::Error>> {
        if codec.chunk_length() > MAX_SAMPLES_PER_CHUNK {
            panic!("Chunk length must below {}", MAX_SAMPLES_PER_CHUNK);
        }

        let local_addr: IpAddr = local_addr_ipv4.into();
        let remote_addr: IpAddr = remote_addr_ipv4.into();

        let secret = secret.map(|s| s.to_owned());
        let et = et.map(|s| s.to_owned());
        let mut latency_frames = std::cmp::max(latency_frames, LATENCY_MIN);

        // strcpy(raopcld->DACP_id, DACP_id ? DACP_id : "");
        // strcpy(raopcld->active_remote, active_remote ? active_remote : "");

        let meta_data_capabilities = MetaDataCapabilities {
            text: md.map(|md| md.contains('0')).unwrap_or(false),
            artwork: md.map(|md| md.contains('1')).unwrap_or(false),
            progress: md.map(|md| md.contains('2')).unwrap_or(false),
        };

        info!("using {} coding", codec);

        let retransmit_mutex = Arc::new(Mutex::new(0));

        let sane_mutex = Arc::new(Mutex::new(Sane {
            ctrl: 0,
            time: 0,
            audio: SaneAudio { avail: 0, select: 0, send: 0 },
        }));

        let seed_sid: u32 = random();
        let seed_sci: u64 = random();

        let sid = format!("{:010}", seed_sid); // sprintf(sid, "%010lu", (long unsigned int) seed.sid);
        let sci = format!("{:016x}", seed_sci); // sprintf(sci, "%016llx", (long long int) seed.sci);

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
            state: RaopState::Down,
            seq_number: random(),
            head_ts: 0,
            pause_ts: 0,
            start_ts: 0,
            first_ts: 0,
            first_pkt: false,
            flushing: true,
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
            let latency: u32 = returned_latency.parse()?;
            if latency > latency_frames { latency_frames = latency; }
        }

        let status_mutex = Arc::new(Mutex::new(status));
        let latency_frames = Arc::new(AtomicU32::new(latency_frames));

        let sync_controller = {
            let status_ref = Arc::clone(&status_mutex);
            let sane_ref = Arc::clone(&sane_mutex);
            let retransmit_ref = Arc::clone(&retransmit_mutex);
            let latency_frames_ref = Arc::clone(&latency_frames);
            let sample_rate = codec.sample_rate();

            SyncController::start(rtp_ctrl, status_ref, sane_ref, retransmit_ref, latency_frames_ref, sample_rate)
        };

        {
            // as connect might take time, state might already have been set
            let mut status = status_mutex.lock().await;
            if status.state == RaopState::Down { status.state = RaopState::Flushed; }
        }

        let rtsp_client_mutex = Arc::new(Mutex::new(rtsp_client));
        let keepalive_controller = KeepaliveController::start(Arc::clone(&rtsp_client_mutex));

        let client = RaopClient {
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

            latency_frames,
            volume: Arc::new(Mutex::new(volume)),

            rtsp_client: rtsp_client_mutex,
        };

        if set_volume {
            client._set_volume().await?;
        }

        Ok(client)
    }

    pub fn float_volume(vol: u8) -> f32 {
        if vol == 0 { return -144.0; }
        if vol >= 100 { return VOLUME_MAX; }

        VOLUME_MIN + ((VOLUME_MAX - VOLUME_MIN) * (vol as f32)) / 100.0
    }

    pub fn latency(&self) -> u32 {
        // Why do AirPlay devices use required latency + 11025?
        self.latency_frames.load(Ordering::Relaxed) + LATENCY_MIN
    }

    pub fn latency_frames_handle(&self) -> Arc<AtomicU32> {
        Arc::clone(&self.latency_frames)
    }

    pub fn sample_rate(&self) -> u32 {
        self.codec.sample_rate()
    }

    pub async fn is_playing(&self) -> bool {
        let now_ts = NtpTime::now().into_timestamp(self.codec.sample_rate());
        trace!("[is_playing] - aquiring status");
        let status = self.status.lock().await;
        trace!("[is_playing] - got status");
        let return_ = status.pause_ts > 0 || now_ts < status.head_ts + (self.latency() as u64);
        trace!("[is_playing] - dropping status");
        return return_;
    }

    pub async fn stop(&self) {
        trace!("[stop] - aquiring status");
        let mut status = self.status.lock().await;
        trace!("[stop] - got status");
        status.flushing = true;
        status.pause_ts = 0;
        trace!("[stop] - dropping status");
    }

    pub async fn accept_frames(&self) -> Result<(), Box<dyn std::error::Error>> {
        let mut first_pkt = false;
        let mut now_ts: u64;

        trace!("[accept_frames] - aquiring status");
        let mut status = self.status.lock().await;
        trace!("[accept_frames] - got status");

        // a flushing is pending
        if status.flushing {
            let now = NtpTime::now();

            now_ts = now.into_timestamp(self.codec.sample_rate());

            // Not flushed yet, but we have time to wait, so pretend we are full
            if status.state != RaopState::Flushed && (!status.start_ts > 0 || status.start_ts > now_ts + self.latency() as u64) {
                unimplemented!();
            }

            // move to streaming only when really flushed - not when timedout
            if status.state == RaopState::Flushed {
                status.first_pkt = true;
                first_pkt = true;
                info!("begining to stream hts:{} n:{}", status.head_ts, now);
                status.state = RaopState::Streaming;
            }

            // unpausing ...
            if status.pause_ts == 0 {
                status.head_ts = if status.start_ts > 0 { status.start_ts } else { now_ts };
                status.first_ts = status.head_ts;

                if first_pkt {
                    let latency_frames = self.latency_frames.load(Ordering::Relaxed);
                    self.sync_controller.send_sync(&mut status, self.codec.sample_rate(), latency_frames, true).await?;
                }

                info!("restarting w/o pause n:{}, hts:{}", now, status.head_ts);
            } else {
                let mut n: u16;
                let mut i: u16;
                let chunks = (self.latency() / self.codec.chunk_length() as u32) as u16;

                // if un-pausing w/o start_time, can anticipate as we have buffer
                status.first_ts = if status.start_ts > 0 { status.start_ts } else { now_ts - self.latency() as u64 };

                // last head_ts shall be first + raopcl_latency - chunk_length
                status.head_ts = status.first_ts - self.codec.chunk_length() as u64;

                if first_pkt {
                    let latency_frames = self.latency_frames.load(Ordering::Relaxed);
                    self.sync_controller.send_sync(&mut status, self.codec.sample_rate(), latency_frames, true).await?;
                }

                info!("restarting w/ pause n:{}, hts:{} (re-send: {})", now, status.head_ts, chunks);

                // search pause_ts in backlog, it should be backward, not too far
                n = status.seq_number;
                i = 0;
                while i < MAX_BACKLOG && status.backlog[(n % MAX_BACKLOG) as usize].as_ref().map(|e| e.timestamp).unwrap_or(0) > status.pause_ts {
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
                        entry.packet.timestamp = status.head_ts as u32;
                        status.first_pkt = false;

                        self._send_audio(&mut status, &entry.packet).await?;

                        // then replace packets in backlog in case
                        let reindex = (status.seq_number % MAX_BACKLOG) as usize;

                        status.backlog[reindex] = Some(BacklogEntry {
                            seq_number: status.seq_number,
                            timestamp: status.head_ts,
                            packet: entry.packet,
                        });

                        status.head_ts += self.codec.chunk_length() as u64;

                        i += 1;
                    }
                }

                debug!("finished resend {}", i);
            }

            status.pause_ts = 0;
            status.start_ts = 0;
            status.flushing = false;
        }

        // when paused, fix "now" at the time when it was paused.
        if status.pause_ts > 0 {
            now_ts = status.pause_ts;
        } else {
            now_ts = NtpTime::now().into_timestamp(self.codec.sample_rate());
        }

        let chunk_length = self.codec.chunk_length() as u64;
        let head_ts = status.head_ts;

        trace!("[accept_frames] - dropping status");
        drop(status);

        if now_ts < head_ts + chunk_length {
            let sleep_frames = (head_ts + chunk_length) - now_ts;
            let sleep_micros = (sleep_frames * 1_000_000) / (self.codec.sample_rate() as u64);
            delay_for(Duration::from_micros(sleep_micros)).await;
        }

        Ok(())
    }

    pub async fn send_chunk(&mut self, sample: &[u8], playtime: &mut u64) -> Result<(), Box<dyn std::error::Error>> {
        let now = NtpTime::now();

        trace!("[send_chunk] - aquiring status");
        let mut status = self.status.lock().await;
        trace!("[send_chunk] - got status");

        /*
        Move to streaming state only when really flushed. In most cases, this is
        done by the raopcl_accept_frames function, except when a player takes too
        long to flush (JBL OnBeat) and we have to "fake" accepting frames
        */
        if status.state == RaopState::Flushed {
            status.first_pkt = true;
            info!("begining to stream (LATE) hts:{} n:{}", status.head_ts, now);
            status.state = RaopState::Streaming;

            let latency_frames = self.latency_frames.load(Ordering::Relaxed);
            self.sync_controller.send_sync(&mut status, self.codec.sample_rate(), latency_frames, true).await?;
        }

        let encoded = self.codec.encode_chunk(&sample);
        let encrypted = self.crypto.encrypt(encoded)?;

        *playtime = TS2NTP(status.head_ts + self.latency() as u64, self.codec.sample_rate());

        trace!("sending audio ts:{} (pt:{}.{} now:{}) ", status.head_ts, SEC(*playtime), FRAC(*playtime), NtpTime::now());

        status.seq_number = status.seq_number.wrapping_add(1);

        let packet = RtpAudioPacket {
            header: RtpHeader {
                proto: 0x80,
                type_: (if status.first_pkt { 0xE0 } else { 0x60 }),
                seq: status.seq_number,
            },
            timestamp: status.head_ts as u32,
            ssrc: (*self.ssrc.lock().await as u32),
            data: encrypted,
        };
        status.first_pkt = false;

        self._send_audio(&mut status, &packet).await?;

        let n = (status.seq_number % MAX_BACKLOG) as usize;

        status.backlog[n] = Some(BacklogEntry {
            seq_number: status.seq_number,
            timestamp: status.head_ts,
            packet: packet,
        });

        status.head_ts += self.codec.chunk_length() as u64;

        if NTP2MS(*playtime) % 10000 < 8 {
            let sane = self.sane.lock().await;
            let retransmit = *self.retransmit.lock().await;
            info!("check n:{} p:{} ts:{} sn:{}\n               retr: {}, avail: {}, send: {}, select: {})",
                now.millis(), MSEC(*playtime), status.head_ts, status.seq_number,
                retransmit, sane.audio.avail, sane.audio.send, sane.audio.select);
        }

        trace!("[send_chunk] - dropping status");

        Ok(())
    }

    async fn _set_volume(&self) -> Result<(), Box<dyn std::error::Error>> {
        if (*self.status.lock().await).state < RaopState::Flushed { return Ok(()); }

        let parameter = format!("volume: {}\r\n", *self.volume.lock().await);
        (*self.rtsp_client.lock().await).set_parameter(&parameter).await?;

        Ok(())
    }

    pub async fn set_volume(&self, vol: f32) -> Result<(), Box<dyn std::error::Error>> {
        if (vol < -30.0 || vol > 0.0) && vol != -144.0 { panic!("Invalid volume"); }
        *self.volume.lock().await = vol;
        return self._set_volume().await;
    }

    pub async fn set_meta_data(&self, meta_data: MetaDataItem) -> Result<(), Box<dyn std::error::Error>> {
        let ts = (*self.status.lock().await).head_ts;
        (*self.rtsp_client.lock().await).set_meta_data(ts, meta_data).await
    }

    pub async fn teardown(mut self) -> Result<(), Box<dyn std::error::Error>> {
        let mut status = self.status.lock().await;
        status.state = RaopState::Down;

        self.keepalive_controller.stop();
        self.sync_controller.stop();
        self.timing_controller.stop();

        let mut rtsp_client = self.rtsp_client.lock().await;
        rtsp_client.flush(status.seq_number + 1, status.head_ts + 1).await?;
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
