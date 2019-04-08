use crate::alac_encoder::AlacEncoder;
use crate::bindings::{get_ntp, rtp_header_t, free, pcm_to_alac_raw, malloc, rtp_sync_pkt_t, ntp_t, usleep, MAX_SAMPLES_PER_CHUNK, RAOP_LATENCY_MIN, aes_context, aes_set_key};
use crate::rtsp_client::RTSPClient;
use crate::rtp::{RtpHeader, RtpAudioPacket, RtpAudioRetransmissionPacket};
use crate::serialization::Serializable;

use std::mem::size_of;
use std::net::{UdpSocket};
use std::net::Ipv4Addr;
use std::ptr;
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::{self, JoinHandle};

use rand::random;
use log::{error, warn, info, debug, trace};

const VOLUME_MIN: f32 = -30.0;
const VOLUME_MAX: f32 = 0.0;
const LATENCY_MIN: u32 = 11025;
const MAX_BACKLOG: u16 = 512;

fn NTP2MS(ntp: u64) -> u64 { (((ntp >> 10) * 1000) >> 22) }
fn TS2NTP(ts: u64, rate: u32) -> u64 { ((((ts as u64) << 16) / (rate as u64)) << 16) }
fn NTP2TS(ntp: u64, rate: u32) -> u64 { (((ntp >> 16) * rate as u64) >> 16) }

fn SEC(ntp: u64) -> u32 { (ntp >> 32) as u32 }
fn FRAC(ntp: u64) -> u32 { ntp as u32 }
fn MSEC(ntp: u64) -> u32 { (((ntp >> 16) * 1000) >> 16) as u32 }

fn safe_get_ntp() -> u64 {
    unsafe { get_ntp(ptr::null_mut()) }
}

unsafe fn any_as_u8_slice<T: Sized>(p: &T) -> &[u8] {
    ::std::slice::from_raw_parts(
        (p as *const T) as *const u8,
        ::std::mem::size_of::<T>(),
    )
}

unsafe fn any_as_u8_slice_len<T: Sized>(p: &T, len: usize) -> &[u8] {
    ::std::slice::from_raw_parts(
        (p as *const T) as *const u8,
        len,
    )
}

unsafe fn any_as_u8_mut_slice<T: Sized>(p: &mut T) -> &mut [u8] {
    ::std::slice::from_raw_parts_mut(
        (p as *mut T) as *mut u8,
        ::std::mem::size_of::<T>(),
    )
}

pub fn analyse_setup(setup_headers: Vec<(String, String)>) -> Result<(u16, u16, u16), Box<std::error::Error>> {
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
pub enum Codec {
    PCM = 0,
    ALACRaw = 1,
    ALAC = 2,
    AAC = 3,
    AALELC = 4,
}

#[derive(Clone, Copy, PartialEq)]
pub enum Crypto {
    Clear = 0,
    RSA = 1,
    FairPlay = 2,
    MFiSAP = 3,
    FairPlaySAP = 4,
}

#[derive(Clone, Copy, PartialEq)]
struct MetaDataCapabilities {
    text: bool,
    artwork: bool,
    progress: bool,
}

struct AesContext {
    ctx: aes_context,
    iv: [u8; 16usize],
    nv: [u8; 16usize],
    key: [u8; 16usize],
}

struct BacklogEntry {
    seq_number: u16,
    timestamp: u64,
    packet: RtpAudioPacket,
}

struct Status {
    state: RaopState,
    seq_number: u16,
    head_ts: u64,
    pause_ts: u64,
    start_ts: u64,
    first_ts: u64,
    first_pkt: bool,
    flushing: bool,
    backlog: [Option<BacklogEntry>; 512usize],
}

struct SaneAudio {
    avail: u64,
    select: u64,
    send: u64,
}

struct Sane {
    ctrl: u64,
    time: u64,
    audio: SaneAudio,
}

pub struct RaopClient {
    // Immutable properties
    remote_addr: Ipv4Addr,
    local_addr: Ipv4Addr,
    rtsp_port: u16,

    auth: bool,

    chunk_length: u32,
    sample_rate: u32,
    sample_size: u32,
    channels: u8,

    codec: Codec,
    crypto: Crypto,
    meta_data_capabilities: MetaDataCapabilities,

    secret: Option<String>,
    et: Option<String>,

    // Mutable properties
    rtp_time: Arc<Mutex<UdpSocket>>,
    rtp_ctrl: Arc<Mutex<UdpSocket>>,
    rtp_audio: Arc<Mutex<UdpSocket>>,

    sane: Arc<Mutex<Sane>>,
    retransmit: Arc<Mutex<u32>>,

    ssrc: Arc<Mutex<u32>>,

    status: Arc<Mutex<Status>>,

    latency_frames: Arc<Mutex<u32>>,
    volume: Arc<Mutex<f32>>,

    aes: Arc<Mutex<AesContext>>,

    time_running: Arc<AtomicBool>,
    time_thread: Arc<Mutex<Option<JoinHandle<()>>>>,

    ctrl_running: Arc<AtomicBool>,
    ctrl_thread: Arc<Mutex<Option<JoinHandle<()>>>>,

    alac_codec: Arc<Mutex<Option<AlacEncoder>>>,
    rtsp_client: Arc<Mutex<RTSPClient>>,
}

impl RaopClient {
    pub fn connect(local_addr: Ipv4Addr, codec: Codec, chunk_length: u32, latency_frames: u32, crypto: Crypto, auth: bool, secret: Option<&str>, et: Option<&str>, md: Option<&str>, sample_rate: u32, sample_size: u32, channels: u8, volume: f32, remote_addr: Ipv4Addr, rtsp_port: u16, set_volume: bool) -> Result<RaopClient, Box<std::error::Error>> {
        if chunk_length > MAX_SAMPLES_PER_CHUNK {
            panic!("Chunk length must below {}", MAX_SAMPLES_PER_CHUNK);
        }

        let secret = secret.map(|s| s.to_owned());
        let et = et.map(|s| s.to_owned());
        let mut latency_frames = std::cmp::max(latency_frames, RAOP_LATENCY_MIN);

        // strcpy(raopcld->DACP_id, DACP_id ? DACP_id : "");
        // strcpy(raopcld->active_remote, active_remote ? active_remote : "");

        let meta_data_capabilities = MetaDataCapabilities {
            text: md.map(|md| md.contains('0')).unwrap_or(false),
            artwork: md.map(|md| md.contains('1')).unwrap_or(false),
            progress: md.map(|md| md.contains('2')).unwrap_or(false),
        };

        let mut codec = codec;
        let mut alac_codec: Option<AlacEncoder>;

        if codec == Codec::ALAC {
            alac_codec = AlacEncoder::new(chunk_length, sample_rate, sample_size, channels);

            if alac_codec.is_none() {
                warn!("cannot create ALAC codec");
                codec = Codec::ALACRaw;
            }
        } else {
            alac_codec = None;
        }

        info!("using {} coding", if alac_codec.is_some() { "ALAC" } else { "PCM" });

        let iv: [u8; 16usize] = random();
        let nv: [u8; 16usize] = iv;
        let mut key: [u8; 16usize] = random();
        let mut ctx = aes_context { erk: [0; 64usize], drk: [0; 64usize], nr: 0 };

        unsafe { aes_set_key(&mut ctx, &mut key[0], 128); }

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
        let mut rtsp_client = RTSPClient::connect((remote_addr, rtsp_port), &sid, "iTunes/7.6.2 (Windows; N;)", &[("Client-Instance", &sci)])?;
        // FIXME:
        // if self.DACP_id[0] != 0 { rtspcl_add_eself.((*s_elient..cnew("DACP-ID").unwrap().into_raw(), self.DACP_id); }
        // if self.active_remote[0] != 0 { rtspclself.esel.f_ient((.s_elient.new("Active-Remote").unwrap().into_raw(), self.active_remote)?;

        info!("local interface {}", rtsp_client.local_ip()?);

        // RTSP pairing verify for AppleTV
        if let Some(ref secret) = secret {
            rtsp_client.pair_verify(secret)?;
        }

        // Send pubkey for MFi devices
        if et.as_ref().map(|et| et.contains('4')).unwrap_or(false) {
            rtsp_client.auth_setup()?;
        }

        let mut sdp = format!(
            "v=0\r\no=iTunes {} 0 IN IP4 {}\r\ns=iTunes\r\nc=IN IP4 {}\r\nt=0 0\r\n",
            sid,
            rtsp_client.local_ip()?,
            remote_addr,
        );

        match codec {
            Codec::ALACRaw => {
                sdp.push_str(format!(
                    "m=audio 0 RTP/AVP 96\r\na=rtpmap:96 AppleLossless\r\na=fmtp:96 {}d 0 {} 40 10 14 {} 255 0 0 {}\r\n",
                    chunk_length,
                    sample_size,
                    channels,
                    sample_rate,
                ).as_str());
            },
            Codec::ALAC => {
                sdp.push_str(format!(
                    "m=audio 0 RTP/AVP 96\r\na=rtpmap:96 AppleLossless\r\na=fmtp:96 {}d 0 {} 40 10 14 {} 255 0 0 {}\r\n",
                    chunk_length,
                    sample_size,
                    channels,
                    sample_rate,
                ).as_str());
            },
            Codec::PCM => {
                sdp.push_str(format!(
                    "m=audio 0 RTP/AVP 96\r\na=rtpmap:96 L{}/{}/{}\r\n",
                    sample_size,
                    sample_rate,
                    channels,
                ).as_str());
            },
            Codec::AAC => panic!("Not implemented"),
            Codec::AALELC => panic!("Not implemented"),
        }

        match crypto {
            Crypto::Clear => {},
            Crypto::RSA => {
                // char *key = NULL, *iv = NULL, *buf;
                // u8_t rsakey[512];
                // int i;
                //
                // i = rsa_encrypt(p->key, 16, rsakey);
                // base64_encode(rsakey, i, &key);
                // remove_char_from_string(key, '=');
                // base64_encode(p->iv, 16, &iv);
                // remove_char_from_string(iv, '=');
                // buf = malloc(strlen(key) + strlen(iv) + 128);
                // sprintf(buf, "a=rsaaeskey:%s\r\n"
                //             "a=aesiv:%s\r\n",
                //             key, iv);
                // strcat(sdp, buf);
                // free(key);
                // free(iv);
                // free(buf);
                // break;
                panic!("unsupported encryption: RSA")
            },
            Crypto::FairPlay => panic!("unsupported encryption: FairPlay"),
            Crypto::FairPlaySAP => panic!("unsupported encryption: FairPlaySAP"),
            Crypto::MFiSAP => panic!("unsupported encryption: MFiSAP"),
        }

        // AppleTV expects now the timing port ot be opened BEFORE the setup message
        let rtp_time = UdpSocket::bind((local_addr, 0))?;
        let local_time_port = rtp_time.local_addr()?.port();
        let rtp_time_mutex = Arc::new(Mutex::new(rtp_time));

        let time_running_mutex = Arc::new(AtomicBool::new(true));
        let time_thread_mutex = {
            let time_running_ref = Arc::clone(&time_running_mutex);
            let rtp_time_ref = Arc::clone(&rtp_time_mutex);

            Arc::new(Mutex::new(Some(thread::spawn(move || { _rtp_timing_thread(time_running_ref, rtp_time_ref); }))))
        };

        // RTSP ANNOUNCE
        if auth && crypto != Crypto::Clear {
            panic!("Not implemented");
            // let seed_sac: [u8; 16] = random();
            // base64_encode(&seed.sac, 16, &sac);
            // remove_char_from_string(sac, '=');
            // rtsp_client.add_exthds("Apple-Challenge", &sac)?;
            // rtsp_client.announce_sdp(&sdp)?;
            // rtsp_client.mark_del_exthds("Apple-Challenge")?;
        } else {
            rtsp_client.announce_sdp(&sdp)?;
        }

        // open RTP sockets, need local ports here before sending SETUP
        let rtp_ctrl = UdpSocket::bind((local_addr, 0))?;
        let local_ctrl_port = rtp_ctrl.local_addr()?.port();

        let rtp_audio = UdpSocket::bind((local_addr, 0))?;
        let local_audio_port = rtp_audio.local_addr()?.port();

        // RTSP SETUP : get all RTP destination ports
        let setup_headers = rtsp_client.setup(local_ctrl_port, local_time_port)?;
        let (remote_audio_port, remote_ctrl_port, remote_time_port) = analyse_setup(setup_headers)?;

        debug!("opened audio socket   l:{:05} r:{}", local_audio_port, remote_audio_port);
        debug!("opened timing socket  l:{:05} r:{}", local_time_port, remote_time_port);
        debug!("opened control socket l:{:05} r:{}", local_ctrl_port, remote_ctrl_port);

        rtp_audio.connect((remote_addr, remote_audio_port))?;
        rtp_ctrl.connect((remote_addr, remote_ctrl_port))?;

        let rtp_ctrl_mutex = Arc::new(Mutex::new(rtp_ctrl));
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

        let record_headers = rtsp_client.record(status.seq_number + 1, NTP2TS(safe_get_ntp(), sample_rate))?;
        let returned_latency = record_headers.iter().find(|header| header.0.to_lowercase() == "audio-latency").map(|header| header.1.as_str());

        if let Some(returned_latency) = returned_latency {
            let latency: u32 = returned_latency.parse()?;
            if latency > latency_frames { latency_frames = latency; }
        }

        let status_mutex = Arc::new(Mutex::new(status));
        let latency_frames_mutex = Arc::new(Mutex::new(latency_frames));

        let ctrl_running_mutex = Arc::new(AtomicBool::new(true));
        let ctrl_thread_mutex = {
            let ctrl_running_ref = Arc::clone(&ctrl_running_mutex);
            let rtp_ctrl_ref = Arc::clone(&rtp_ctrl_mutex);
            let status_ref = Arc::clone(&status_mutex);
            let sane_ref = Arc::clone(&sane_mutex);
            let retransmit_ref = Arc::clone(&retransmit_mutex);
            let latency_frames_ref = Arc::clone(&latency_frames_mutex);

            Arc::new(Mutex::new(Some(thread::spawn(move || { _rtp_control_thread(ctrl_running_ref, rtp_ctrl_ref, status_ref, sane_ref, retransmit_ref, latency_frames_ref, sample_rate); }))))
        };

        {
            // as connect might take time, state might already have been set
            let mut status = status_mutex.lock().unwrap();
            if status.state == RaopState::Down { status.state = RaopState::Flushed; }
        }

        let client = RaopClient {
            // Immutable properties
            remote_addr,
            local_addr,
            rtsp_port,
            auth,
            chunk_length,
            sample_rate,
            sample_size,
            channels,
            codec,
            crypto,
            meta_data_capabilities,
            secret,
            et,

            // Mutable properties
            rtp_time: rtp_time_mutex,
            rtp_ctrl: rtp_ctrl_mutex,
            rtp_audio: rtp_audio_mutex,

            sane: sane_mutex,

            retransmit: retransmit_mutex,
            ssrc: Arc::new(Mutex::new(random())),

            status: status_mutex,

            latency_frames: latency_frames_mutex,
            volume: Arc::new(Mutex::new(volume)),

            aes: Arc::new(Mutex::new(AesContext { ctx, iv, nv, key })),

            time_running: time_running_mutex,
            time_thread: time_thread_mutex,
            ctrl_running: ctrl_running_mutex,
            ctrl_thread: ctrl_thread_mutex,

            alac_codec: Arc::new(Mutex::new(alac_codec)),
            rtsp_client: Arc::new(Mutex::new(rtsp_client)),
        };

        if set_volume {
            client._set_volume()?;
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
        *self.latency_frames.lock().unwrap() + LATENCY_MIN
    }

    pub fn sample_rate(&self) -> u32 {
        self.sample_rate
    }

    pub fn is_playing(&self) -> bool {
        let now_ts = NTP2TS(safe_get_ntp(), self.sample_rate);
        trace!("[is_playing] - aquiring status");
        let status = self.status.lock().unwrap();
        trace!("[is_playing] - got status");
        let return_ = status.pause_ts > 0 || now_ts < status.head_ts + (self.latency() as u64);
        trace!("[is_playing] - dropping status");
        return return_;
    }

    pub fn accept_frames(&self) -> Result<bool, Box<std::error::Error>> {
        let mut first_pkt = false;
        let mut now_ts: u64;

        trace!("[accept_frames] - aquiring status");
        let mut status = self.status.lock().unwrap();
        trace!("[accept_frames] - got status");

        // a flushing is pending
        if status.flushing {
            let now = safe_get_ntp();

            now_ts = NTP2TS(now, self.sample_rate);

            // Not flushed yet, but we have time to wait, so pretend we are full
            if status.state != RaopState::Flushed && (!status.start_ts > 0 || status.start_ts > now_ts + self.latency() as u64) {
                return Ok(false);
            }

            // move to streaming only when really flushed - not when timedout
            if status.state == RaopState::Flushed {
                status.first_pkt = true;
                first_pkt = true;
                info!("begining to stream hts:{} n:{}.{}", status.head_ts, SEC(now), FRAC(now));
                status.state = RaopState::Streaming;
            }

            // unpausing ...
            if status.pause_ts == 0 {
                status.head_ts = if status.start_ts > 0 { status.start_ts } else { now_ts };
                status.first_ts = status.head_ts;

                if first_pkt {
                    trace!("[accept_frames] - aquiring ctrl socket");
                    let socket = self.rtp_ctrl.lock().unwrap();
                    trace!("[accept_frames] - got ctrl socket");
                    trace!("[accept_frames] - aquiring latency_frames");
                    let latency_frames = self.latency_frames.lock().unwrap();
                    trace!("[accept_frames] - got latency_frames");
                    _send_sync(&socket, &mut status, self.sample_rate, *latency_frames, true)?;
                    trace!("[accept_frames] - dropping latency_frames");
                    trace!("[accept_frames] - dropping ctrl socket");
                }

                info!("restarting w/o pause n:{}.{}, hts:{}", SEC(now), FRAC(now), status.head_ts);
            } else {
                let mut n: u16;
                let mut i: u16;
                let chunks = (self.latency() / self.chunk_length as u32) as u16;

                // if un-pausing w/o start_time, can anticipate as we have buffer
                status.first_ts = if status.start_ts > 0 { status.start_ts } else { now_ts - self.latency() as u64 };

                // last head_ts shall be first + raopcl_latency - chunk_length
                status.head_ts = status.first_ts - self.chunk_length as u64;

                if first_pkt {
                    trace!("[accept_frames] - aquiring ctrl socket");
                    let socket = self.rtp_ctrl.lock().unwrap();
                    trace!("[accept_frames] - got ctrl socket");
                    trace!("[accept_frames] - aquiring latency_frames");
                    let latency_frames = self.latency_frames.lock().unwrap();
                    trace!("[accept_frames] - got latency_frames");
                    _send_sync(&socket, &mut status, self.sample_rate, *latency_frames, true)?;
                    trace!("[accept_frames] - dropping latency_frames");
                    trace!("[accept_frames] - dropping ctrl socket");
                }

                info!("restarting w/ pause n:{}.{}, hts:{} (re-send: {})", SEC(now), FRAC(now), status.head_ts, chunks);

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

                        self._send_audio(&mut status, &entry.packet)?;

                        // then replace packets in backlog in case
                        let reindex = (status.seq_number % MAX_BACKLOG) as usize;

                        status.backlog[reindex] = Some(BacklogEntry {
                            seq_number: status.seq_number,
                            timestamp: status.head_ts,
                            packet: entry.packet,
                        });

                        status.head_ts += self.chunk_length as u64;

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
            now_ts = NTP2TS(safe_get_ntp(), self.sample_rate);
        }

        let accept = now_ts >= status.head_ts + (self.chunk_length as u64);

        trace!("[accept_frames] - dropping status");
        return Ok(accept);
    }

    pub fn send_chunk(&self, sample: &mut [u8], frames: usize, playtime: &mut u64) -> Result<(), Box<std::error::Error>> {
        let now = safe_get_ntp();

        trace!("[send_chunk] - aquiring status");
        let mut status = self.status.lock().unwrap();
        trace!("[send_chunk] - got status");

        /*
        Move to streaming state only when really flushed. In most cases, this is
        done by the raopcl_accept_frames function, except when a player takes too
        long to flush (JBL OnBeat) and we have to "fake" accepting frames
        */
        if status.state == RaopState::Flushed {
            status.first_pkt = true;
            info!("begining to stream (LATE) hts:{} n:{}.{}", status.head_ts, SEC(now), FRAC(now));
            status.state = RaopState::Streaming;

            trace!("[send_chunk] - aquiring ctrl socket");
            let socket = self.rtp_ctrl.lock().unwrap();
            trace!("[send_chunk] - got ctrl socket");
            trace!("[send_chunk] - aquiring latency_frames");
            let latency_frames = self.latency_frames.lock().unwrap();
            trace!("[send_chunk] - got latency_frames");
            _send_sync(&socket, &mut status, self.sample_rate, *latency_frames, true)?;
            trace!("[send_chunk] - dropping latency_frames");
            trace!("[send_chunk] - dropping ctrl socket");
        }

        let mut encoded: *mut u8 = ptr::null_mut();
        let mut size: i32 = 0;

        match self.codec {
            Codec::ALAC => {
                let alac_codec = self.alac_codec.lock().unwrap();
                alac_codec.as_ref().unwrap().encode_chunk(sample, frames, &mut encoded, &mut size);
            },
            Codec::ALACRaw => {
                unsafe { pcm_to_alac_raw(&mut (*sample)[0], frames as i32, &mut encoded, &mut size, self.chunk_length as i32); }
            },
            Codec::PCM => {
                size = (frames * 4) as i32;
                encoded = unsafe { malloc(frames * 4) as *mut u8 };
                for offset in (0..(size as usize)).step_by(4) {
                    unsafe {
                        *encoded.offset((offset + 0) as isize) = sample[offset + 1];
                        *encoded.offset((offset + 1) as isize) = sample[offset + 0];
                        *encoded.offset((offset + 2) as isize) = sample[offset + 3];
                        *encoded.offset((offset + 3) as isize) = sample[offset + 2];
                    }
                }
            }
            _ => {
                panic!("Not implemented");
            }
        }

        *playtime = TS2NTP(status.head_ts + self.latency() as u64, self.sample_rate);

        trace!("sending audio ts:{} (pt:{}.{} now:{}) ", status.head_ts, SEC(*playtime), FRAC(*playtime), safe_get_ntp());

        status.seq_number = status.seq_number.wrapping_add(1);

        let packet = RtpAudioPacket {
            header: RtpHeader {
                proto: 0x80,
                type_: (if status.first_pkt { 0xE0 } else { 0x60 }),
                seq: status.seq_number,
            },
            timestamp: status.head_ts as u32,
            ssrc: (*self.ssrc.lock().unwrap() as u32),
            data: unsafe { std::slice::from_raw_parts(encoded, size as usize).to_vec() },
        };
        status.first_pkt = false;

        // with newer airport express, don't use encryption (??)
        if self.crypto != Crypto::Clear {
            panic!("Not implemented");
            // raopcl_encrypt(p, (u8_t*) packet + sizeof(rtp_audio_pkt_t), size);
        }

        self._send_audio(&mut status, &packet)?;

        let n = (status.seq_number % MAX_BACKLOG) as usize;

        status.backlog[n] = Some(BacklogEntry {
            seq_number: status.seq_number,
            timestamp: status.head_ts,
            packet: packet,
        });

        status.head_ts += self.chunk_length as u64;

        if NTP2MS(*playtime) % 10000 < 8 {
            let sane = self.sane.lock().unwrap();
            let retransmit = *self.retransmit.lock().unwrap();
            info!("check n:{} p:{} ts:{} sn:{}\n               retr: {}, avail: {}, send: {}, select: {})",
                MSEC(now), MSEC(*playtime), status.head_ts, status.seq_number,
                retransmit, sane.audio.avail, sane.audio.send, sane.audio.select);
        }

        unsafe { free(encoded as *mut std::ffi::c_void); }

        trace!("[send_chunk] - dropping status");

        Ok(())
    }

    fn _set_volume(&self) -> Result<(), Box<std::error::Error>> {
        if (*self.status.lock().unwrap()).state < RaopState::Flushed { return Ok(()); }

        let parameter = format!("volume: {}\r\n", *self.volume.lock().unwrap());
        (*self.rtsp_client.lock().unwrap()).set_parameter(&parameter)?;

        Ok(())
    }

    pub fn set_volume(&self, vol: f32) -> Result<(), Box<std::error::Error>> {
        if (vol < -30.0 || vol > 0.0) && vol != -144.0 { panic!("Invalid volume"); }
        *self.volume.lock().unwrap() = vol;
        return self._set_volume();
    }

    fn _send_audio(&self, status: &mut Status, packet: &RtpAudioPacket) -> Result<bool, Box<std::error::Error>> {
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

        /*
        The audio socket is non blocking, so we can can wait socket availability
        but not too much. Half of the packet size if a good value. There is the
        backlog buffer to re-send packets if needed, so nothign is lost

        FIXME: This is no longer implemented :(
        */
        let socket = self.rtp_audio.lock().unwrap();
        let n = socket.send(&packet.as_bytes()).unwrap();
        drop(socket);

        let mut ret = true;

        {
            let mut sane = self.sane.lock().unwrap();

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

impl Drop for RaopClient {
    fn drop(&mut self) {
        let mut status = self.status.lock().unwrap();
        status.state = RaopState::Down;

        self.ctrl_running.store(false, Ordering::Relaxed);
        self.ctrl_thread.lock().unwrap().take().map(|ctrl_thread| ctrl_thread.join());

        self.time_running.store(false, Ordering::Relaxed);
        self.time_thread.lock().unwrap().take().map(|time_thread| time_thread.join());

        let mut rtsp_client = self.rtsp_client.lock().unwrap();
        rtsp_client.flush(status.seq_number + 1, status.head_ts + 1).unwrap();
    }
}

fn _send_sync(socket: &UdpSocket, status: &mut Status, sample_rate: u32, latency_frames: u32, first: bool) -> Result<(), Box<std::error::Error>> {
    // do not send timesync on FLUSHED
    if status.state != RaopState::Streaming { return Ok(()); }

    let timestamp = status.head_ts;
    let now = TS2NTP(timestamp, sample_rate);

    let rsp = rtp_sync_pkt_t {
        hdr: rtp_header_t {
            proto: 0x80 | if first { 0x10 } else { 0x00 },
            type_: 0x54 | 0x80,
            // seems that seq=7 shall be forced
            seq: [0, 7],
        },

        // set the NTP time in network order
        curr_time: ntp_t {
            seconds: SEC(now).to_be(),
            fraction: FRAC(now).to_be(),
        },

        // The DAC time is synchronized with gettime_ms(), minus the latency.
        rtp_timestamp: (timestamp as u32).to_be(),
        rtp_timestamp_latency: ((timestamp - latency_frames as u64) as u32).to_be(),
    };

    let n = socket.send(unsafe { any_as_u8_slice(&rsp) })?;

    debug!("sync ntp:{}.{} (ts:{})", SEC(now), FRAC(now), status.head_ts);

    if n == 0 { info!("write, disconnected on the other end"); }

    Ok(())
}

#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
struct rtp_time_pkt_t {
    hdr: rtp_header_t,
    dummy: u32,
    ref_time: ntp_t,
    recv_time: ntp_t,
    send_time: ntp_t,
}

impl rtp_time_pkt_t {
    pub fn new() -> rtp_time_pkt_t {
        rtp_time_pkt_t {
            hdr: rtp_header_t {
                proto: 0,
                type_: 0,
                seq: [0; 2usize],
            },
            dummy: 0,
            ref_time: ntp_t { seconds: 0, fraction: 0 },
            recv_time: ntp_t { seconds: 0, fraction: 0 },
            send_time: ntp_t { seconds: 0, fraction: 0 },
        }
    }
}

fn _rtp_timing_thread(running: Arc<AtomicBool>, socket_mutex: Arc<Mutex<UdpSocket>>) {
    // FIXME: this should come from the UdpSocket
    let mut connected = false;

    while running.load(Ordering::Relaxed) {
        let socket = socket_mutex.lock().unwrap();

        let mut req = rtp_time_pkt_t::new();
        let mut n: usize;

        if connected {
            n = socket.recv(unsafe { any_as_u8_mut_slice(&mut req) }).unwrap();
        } else {
            let (_n, client) = socket.recv_from(unsafe { any_as_u8_mut_slice(&mut req) }).unwrap();
            n = _n;
            debug!("NTP remote port: {}", client.port());
            socket.connect(client).unwrap();
            connected = true;
        }

        if n > 0 {
            let mut rsp = rtp_time_pkt_t::new();

            rsp.hdr = req.hdr;
            rsp.hdr.type_ = 0x53 | 0x80;
            // just copy the request header or set seq=7 and timestamp=0
            rsp.ref_time = req.send_time;

            // transform timeval into NTP and set network order
            unsafe { get_ntp(&mut rsp.recv_time); }

            rsp.recv_time.seconds = rsp.recv_time.seconds.to_be();
            rsp.recv_time.fraction = rsp.recv_time.fraction.to_be();
            rsp.send_time = rsp.recv_time; // might need to add a few fraction ?

            n = socket.send(unsafe { any_as_u8_slice(&rsp) }).unwrap();

            if n != size_of::<rtp_time_pkt_t>() {
                error!("error responding to sync");
            }

            debug!("NTP sync: {}.{} (ref {}.{})", u32::from_be(rsp.send_time.seconds), u32::from_be(rsp.send_time.fraction),
                                                    u32::from_be(rsp.ref_time.seconds), u32::from_be(rsp.ref_time.fraction));

        }

        drop(socket);

        if n == 0 {
            error!("read, disconnected on the other end");
            unsafe { usleep(100000); }
            continue;
        }

        thread::sleep(::std::time::Duration::from_millis(20));
    }
}

#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
struct rtp_lost_pkt_t {
    hdr: rtp_header_t,
    seq_number: u16,
    n: u16,
}

impl rtp_lost_pkt_t {
    pub fn new() -> rtp_lost_pkt_t {
        rtp_lost_pkt_t {
            hdr: rtp_header_t {
                proto: 0,
                type_: 0,
                seq: [0; 2usize],
            },
            seq_number: 0,
            n: 0,
        }
    }
}

fn _rtp_control_thread(running: Arc<AtomicBool>, socket_mutex: Arc<Mutex<UdpSocket>>, status_mutex: Arc<Mutex<Status>>, sane_mutex: Arc<Mutex<Sane>>, retransmit_mutex: Arc<Mutex<u32>>, latency_frames_mutex: Arc<Mutex<u32>>, sample_rate: u32) {
    // NOTE: socket _must_ be connected here
    {
        socket_mutex.lock().unwrap().set_nonblocking(true).unwrap();
    }

    // Reuse this memory for receiving packet
    let mut lost = rtp_lost_pkt_t::new();

    while running.load(Ordering::Relaxed) {
        trace!("[_rtp_control_thread] - aquiring ctrl socket");
        let socket = socket_mutex.lock().unwrap();
        trace!("[_rtp_control_thread] - got ctrl socket");

        let n = match socket.recv(unsafe { any_as_u8_mut_slice(&mut lost) }) {
            Ok(n) => Some(n),
            Err(ref e) if e.kind() == ::std::io::ErrorKind::WouldBlock => None,
            Err(e) => panic!("encountered IO error: {}", e),
        };

        trace!("[_rtp_control_thread] - {}", if n.is_none() { "would block" } else { "received" });

        if let Some(n) = n {
            lost.seq_number = u16::from_be(lost.seq_number);
            lost.n = u16::from_be(lost.n);

            {
                let mut sane = sane_mutex.lock().unwrap();

                if n != size_of::<rtp_lost_pkt_t>() {
                    error!("error in received request sn:{} n:{} (recv:{})", unsafe { lost.seq_number }, unsafe { lost.n }, n);
                    lost.n = 0;
                    lost.seq_number = 0;
                    sane.ctrl += 1;
                } else {
                    sane.ctrl = 0;
                }
            }

            let mut missed: i32 = 0;
            if lost.n > 0 {
                let status = status_mutex.lock().unwrap();

                for i in 0..lost.n {
                    let index = ((lost.seq_number + i) % MAX_BACKLOG) as usize;

                    if status.backlog[index].as_ref().map(|e| e.seq_number).unwrap_or(0) == lost.seq_number + i {
                        if let Some(ref entry) = status.backlog[index] {
                            *retransmit_mutex.lock().unwrap() += 1;
                            socket.send(&RtpAudioRetransmissionPacket::wrap(&entry.packet).as_bytes()).unwrap();
                        } else {
                            // packet have been released meanwhile, be extra cautious
                            missed += 1;
                        }
                    } else {
                        warn!("lost packet out of backlog {}", lost.seq_number + i);
                    }
                }
            }

            debug!("retransmit packet sn:{} nb:{} (mis:{})", unsafe { lost.seq_number }, unsafe { lost.n }, missed);

            continue;
        }

        {
            trace!("[_rtp_control_thread] - aquiring status");
            let mut status = status_mutex.lock().unwrap();
            trace!("[_rtp_control_thread] - got status");
            trace!("[_rtp_control_thread] - aquiring latency_frames");
            let latency_frames = latency_frames_mutex.lock().unwrap();
            trace!("[_rtp_control_thread] - got latency_frames");
            _send_sync(&socket, &mut status, sample_rate, *latency_frames, false).unwrap();
            trace!("[_rtp_control_thread] - dropping latency_frames");
            trace!("[_rtp_control_thread] - dropping status");
        }

        drop(socket);
        trace!("[_rtp_control_thread] - dropping socket");

        thread::sleep(std::time::Duration::from_secs(1));
    }
}
