use crate::alac_encoder::AlacEncoder;
use crate::bindings::{raop_state_t, raop_states_s_RAOP_DOWN, raop_states_s_RAOP_FLUSHED, raop_states_s_RAOP_STREAMING};
use crate::bindings::{key_data_t, free_kd, get_ntp, kd_lookup, rtp_header_t, rtp_audio_pkt_t, free, pcm_to_alac_raw, malloc, rtp_sync_pkt_t, ntp_t, usleep, MAX_SAMPLES_PER_CHUNK, RAOP_LATENCY_MIN, rtp_port_s, sock_info_s, aes_context, aes_set_key, raopcl_s__bindgen_ty_1, raopcl_s__bindgen_ty_2, raopcl_s__bindgen_ty_1__bindgen_ty_1};
use crate::rtsp_client::RTSPClient;

use std::ffi::{CStr, CString};
use std::mem::size_of;
use std::net::{UdpSocket};
use std::net::Ipv4Addr;
use std::ptr;
use std::rc::Rc;
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

struct Status {
    state: raop_state_t,
    seq_number: u16,
    head_ts: u64,
    pause_ts: u64,
    start_ts: u64,
    first_ts: u64,
    first_pkt: bool,
    flushing: bool,
    backlog: [raopcl_s__bindgen_ty_2; 512usize],
}

#[derive(Clone)]
pub struct RaopClient {
    // Immutable copied properties
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

    // Immutable shared properties
    secret: Rc<Option<String>>,
    et: Rc<Option<String>>,

    // Mutable properties
    rtp_time: Arc<Mutex<Option<UdpSocket>>>,
    rtp_ctrl: Arc<Mutex<Option<UdpSocket>>>,
    rtp_audio: Arc<Mutex<Option<UdpSocket>>>,

    sane: Arc<Mutex<raopcl_s__bindgen_ty_1>>,
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

unsafe impl Send for RaopClient {}

impl RaopClient {
    pub fn new(local_addr: Ipv4Addr, codec: Codec, chunk_length: u32, latency_frames: u32, crypto: Crypto, auth: bool, secret: Option<&str>, et: Option<&str>, md: Option<&str>, sample_rate: u32, sample_size: u32, channels: u8, volume: f32, remote_addr: Ipv4Addr, rtsp_port: u16) -> Option<RaopClient> {
        if chunk_length > MAX_SAMPLES_PER_CHUNK {
            error!("Chunk length must below {}", MAX_SAMPLES_PER_CHUNK);
            return None;
        }

        let secret = secret.map(|s| s.to_owned());
        let et = et.map(|s| s.to_owned());
        let latency_frames = std::cmp::max(latency_frames, RAOP_LATENCY_MIN);

        // strcpy(raopcld->DACP_id, DACP_id ? DACP_id : "");
        // strcpy(raopcld->active_remote, active_remote ? active_remote : "");

        let meta_data_capabilities = MetaDataCapabilities {
            text: md.map(|md| md.contains('0')).unwrap_or(false),
            artwork: md.map(|md| md.contains('1')).unwrap_or(false),
            progress: md.map(|md| md.contains('2')).unwrap_or(false),
        };

        let rtsp_client = RTSPClient::new("iTunes/7.6.2 (Windows; N;)");
        if rtsp_client.is_none() { error!("Cannot create RTSP context"); return None; }
        let rtsp_client = rtsp_client.unwrap();

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

        Some(RaopClient {
            // Immutable copied properties
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

            // Immutable shared properties
            secret: Rc::new(secret),
            et: Rc::new(et),

            // Mutable properties
            rtp_time: Arc::new(Mutex::new(None)),
            rtp_ctrl: Arc::new(Mutex::new(None)),
            rtp_audio: Arc::new(Mutex::new(None)),

            sane: Arc::new(Mutex::new(raopcl_s__bindgen_ty_1 {
                ctrl: 0,
                time: 0,
                audio: raopcl_s__bindgen_ty_1__bindgen_ty_1 { avail: 0, select: 0, send: 0 },
            })),

            retransmit: Arc::new(Mutex::new(0)),
            ssrc: Arc::new(Mutex::new(0)),

            status: Arc::new(Mutex::new(Status {
                state: raop_states_s_RAOP_DOWN,
                seq_number: random(),
                head_ts: 0,
                pause_ts: 0,
                start_ts: 0,
                first_ts: 0,
                first_pkt: false,
                flushing: true,
                backlog: [raopcl_s__bindgen_ty_2 { seq_number: 0, timestamp: 0, size: 0, buffer: ptr::null_mut() }; 512usize],
            })),

            latency_frames: Arc::new(Mutex::new(latency_frames)),
            volume: Arc::new(Mutex::new(volume)),

            aes: Arc::new(Mutex::new(AesContext { ctx, iv, nv, key })),

            time_running: Arc::new(AtomicBool::new(false)),
            time_thread: Arc::new(Mutex::new(None)),
            ctrl_running: Arc::new(AtomicBool::new(false)),
            ctrl_thread: Arc::new(Mutex::new(None)),

            alac_codec: Arc::new(Mutex::new(alac_codec)),
            rtsp_client: Arc::new(Mutex::new(rtsp_client)),
        })
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
        let now_ts = NTP2TS(safe_get_ntp(), self.sample_rate());
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

            now_ts = NTP2TS(now, self.sample_rate());

            // Not flushed yet, but we have time to wait, so pretend we are full
            if status.state != raop_states_s_RAOP_FLUSHED && (!status.start_ts > 0 || status.start_ts > now_ts + self.latency() as u64) {
                return Ok(false);
            }

            // move to streaming only when really flushed - not when timedout
            if status.state == raop_states_s_RAOP_FLUSHED {
                status.first_pkt = true;
                first_pkt = true;
                info!("begining to stream hts:{} n:{}.{}", status.head_ts, SEC(now), FRAC(now));
                status.state = raop_states_s_RAOP_STREAMING;
            }

            // unpausing ...
            if status.pause_ts == 0 {
                status.head_ts = if status.start_ts > 0 { status.start_ts } else { now_ts };
                status.first_ts = status.head_ts;
                if first_pkt { self._send_sync(&mut status, true)?; }
                info!("restarting w/o pause n:{}.{}, hts:{}", SEC(now), FRAC(now), status.head_ts);
            } else {
                let mut n: u16;
                let mut i: u16;
                let chunks = (self.latency() / self.chunk_length as u32) as u16;

                // if un-pausing w/o start_time, can anticipate as we have buffer
                status.first_ts = if status.start_ts > 0 { status.start_ts } else { now_ts - self.latency() as u64 };

                // last head_ts shall be first + raopcl_latency - chunk_length
                status.head_ts = status.first_ts - self.chunk_length as u64;

                if first_pkt { self._send_sync(&mut status, true)?; }

                info!("restarting w/ pause n:{}.{}, hts:{} (re-send: {})", SEC(now), FRAC(now), status.head_ts, chunks);

                // search pause_ts in backlog, it should be backward, not too far
                n = status.seq_number;
                i = 0;
                while i < MAX_BACKLOG && status.backlog[(n % MAX_BACKLOG) as usize].timestamp > status.pause_ts {
                    i += 1;
                    n -= 1;
                }

                // the resend shall go up to (including) pause_ts
                n = (n - chunks + 1) % MAX_BACKLOG;

                // re-send old packets
                i = 0;
                while i < chunks {
                    let index = ((n + i) % MAX_BACKLOG) as usize;

                    if status.backlog[index].buffer.is_null() { continue; }

                    status.seq_number += 1;

                    let mut packet: *mut rtp_audio_pkt_t;
                    unsafe {
                        packet = status.backlog[index].buffer.offset(size_of::<rtp_header_t>() as isize) as *mut rtp_audio_pkt_t;
                        (*packet).hdr.seq[0] = ((status.seq_number >> 8) & 0xff) as u8;
                        (*packet).hdr.seq[1] = (status.seq_number & 0xff) as u8;
                        (*packet).timestamp = (status.head_ts as u32).to_be();
                        (*packet).hdr.type_ = 0x60 | (if status.first_pkt { 0x80 } else { 0 });
                        status.first_pkt = false;
                    }

                    // then replace packets in backlog in case
                    let reindex = (status.seq_number % MAX_BACKLOG) as usize;

                    status.backlog[reindex].seq_number = status.seq_number;
                    status.backlog[reindex].timestamp = status.head_ts;
                    if !status.backlog[reindex].buffer.is_null() { unsafe { free(status.backlog[reindex].buffer as *mut std::ffi::c_void); } }
                    status.backlog[reindex].buffer = status.backlog[index].buffer;
                    status.backlog[reindex].size = status.backlog[index].size;
                    status.backlog[index].buffer = ptr::null_mut();

                    status.head_ts += self.chunk_length as u64;

                    let size = status.backlog[reindex].size as usize;
                    self._send_audio(&mut status, packet, size)?;

                    i += 1;
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
            now_ts = NTP2TS(safe_get_ntp(), self.sample_rate());
        }

        let accept = now_ts >= status.head_ts + (self.chunk_length as u64);

        trace!("[accept_frames] - dropping status");
        return Ok(accept);
    }

    pub fn send_chunk(&self, sample: &mut [u8], frames: usize, playtime: &mut u64) -> Result<(), Box<std::error::Error>> {
        unsafe {
            let now = safe_get_ntp();

            trace!("[send_chunk] - aquiring status");
            let mut status = self.status.lock().unwrap();
            trace!("[send_chunk] - got status");

            /*
            Move to streaming state only when really flushed. In most cases, this is
            done by the raopcl_accept_frames function, except when a player takes too
            long to flush (JBL OnBeat) and we have to "fake" accepting frames
            */
            if status.state == raop_states_s_RAOP_FLUSHED {
                status.first_pkt = true;
                info!("begining to stream (LATE) hts:{} n:{}.{}", status.head_ts, SEC(now), FRAC(now));
                status.state = raop_states_s_RAOP_STREAMING;
                self._send_sync(&mut status, true)?;
            }

            let mut encoded: *mut u8 = ptr::null_mut();
            let mut size: i32 = 0;

            match self.codec {
                Codec::ALAC => {
                    let alac_codec = self.alac_codec.lock().unwrap();
                    alac_codec.as_ref().unwrap().encode_chunk(sample, frames, &mut encoded, &mut size);
                },
                Codec::ALACRaw => {
                    pcm_to_alac_raw(&mut (*sample)[0], frames as i32, &mut encoded, &mut size, self.chunk_length as i32);
                },
                Codec::PCM => {
                    size = (frames * 4) as i32;
                    encoded = malloc(frames * 4) as *mut u8;
                    for offset in (0..(size as usize)).step_by(4) {
                        *encoded.offset((offset + 0) as isize) = sample[offset + 1];
                        *encoded.offset((offset + 1) as isize) = sample[offset + 0];
                        *encoded.offset((offset + 2) as isize) = sample[offset + 3];
                        *encoded.offset((offset + 3) as isize) = sample[offset + 2];
                    }
                }
                _ => {
                    panic!("Not implemented");
                }
            }

            let buffer = malloc(size_of::<rtp_header_t>() + size_of::<rtp_audio_pkt_t>() + size as usize) as *mut u8;

            if buffer.is_null() {
                free(encoded as *mut std::ffi::c_void);
                error!("cannot allocate buffer");
                panic!("Cannot allocate buffer");
            }

            *playtime = TS2NTP(status.head_ts + self.latency() as u64, self.sample_rate());

            trace!("sending audio ts:{} (pt:{}.{} now:{}) ", status.head_ts, SEC(*playtime), FRAC(*playtime), safe_get_ntp());

            status.seq_number = status.seq_number.wrapping_add(1);

            // packet is after re-transmit header
            // packet = (rtp_audio_pkt_t *) (buffer + sizeof(rtp_header_t));
            let packet = buffer.offset(size_of::<rtp_header_t>() as isize) as *mut rtp_audio_pkt_t;
            (*packet).hdr.proto = 0x80;
            (*packet).hdr.type_ = 0x60 | (if status.first_pkt { 0x80 } else { 0 });
            status.first_pkt = false;
            (*packet).hdr.seq[0] = ((status.seq_number >> 8) & 0xff) as u8;
            (*packet).hdr.seq[1] = (status.seq_number & 0xff) as u8;
            (*packet).timestamp = (status.head_ts as u32).to_be();
            (*packet).ssrc = (*self.ssrc.lock().unwrap() as u32).to_be();

            buffer.offset((size_of::<rtp_header_t>() + size_of::<rtp_audio_pkt_t>()) as isize).copy_from(encoded, size as usize);

            // with newer airport express, don't use encryption (??)
            if self.crypto != Crypto::Clear {
                panic!("Not implemented");
                // raopcl_encrypt(p, (u8_t*) packet + sizeof(rtp_audio_pkt_t), size);
            }

            let n = (status.seq_number % MAX_BACKLOG) as usize;
            status.backlog[n].seq_number = status.seq_number;
            status.backlog[n].timestamp = status.head_ts;
            if !status.backlog[n].buffer.is_null() { free(status.backlog[n].buffer as *mut std::ffi::c_void); }
            status.backlog[n].buffer = buffer;
            status.backlog[n].size = (size_of::<rtp_audio_pkt_t>() as i32) + size;

            status.head_ts += self.chunk_length as u64;

            self._send_audio(&mut status, packet, size_of::<rtp_audio_pkt_t>() + (size as usize))?;

            if NTP2MS(*playtime) % 10000 < 8 {
                let sane = *self.sane.lock().unwrap();
                let retransmit = *self.retransmit.lock().unwrap();
                info!("check n:{} p:{} ts:{} sn:{}\n               retr: {}, avail: {}, send: {}, select: {})",
                    MSEC(now), MSEC(*playtime), status.head_ts, status.seq_number,
                    retransmit, sane.audio.avail, sane.audio.send, sane.audio.select);
            }

            free(encoded as *mut std::ffi::c_void);

            trace!("[send_chunk] - dropping status");
        }

        Ok(())
    }

    fn _set_volume(&self) -> Result<(), Box<std::error::Error>> {
        if (*self.status.lock().unwrap()).state < raop_states_s_RAOP_FLUSHED { return Ok(()); }

        let parameter = format!("volume: {}\r\n", *self.volume.lock().unwrap());
        (*self.rtsp_client.lock().unwrap()).set_parameter(&parameter)?;

        Ok(())
    }

    pub fn set_volume(&self, vol: f32) -> Result<(), Box<std::error::Error>> {
        if (vol < -30.0 || vol > 0.0) && vol != -144.0 { panic!("Invalid volume"); }
        *self.volume.lock().unwrap() = vol;
        return self._set_volume();
    }

    pub fn set_sdp(&self, sdp: &mut String) {
        match self.codec {
            Codec::ALACRaw => {
                sdp.push_str(format!(
                    "m=audio 0 RTP/AVP 96\r\na=rtpmap:96 AppleLossless\r\na=fmtp:96 {}d 0 {} 40 10 14 {} 255 0 0 {}\r\n",
                    self.chunk_length,
                    self.sample_size,
                    self.channels,
                    self.sample_rate(),
                ).as_str());
            },
            Codec::ALAC => {
                sdp.push_str(format!(
                    "m=audio 0 RTP/AVP 96\r\na=rtpmap:96 AppleLossless\r\na=fmtp:96 {}d 0 {} 40 10 14 {} 255 0 0 {}\r\n",
                    self.chunk_length,
                    self.sample_size,
                    self.channels,
                    self.sample_rate(),
                ).as_str());
            },
            Codec::PCM => {
                sdp.push_str(format!(
                    "m=audio 0 RTP/AVP 96\r\na=rtpmap:96 L{}/{}/{}\r\n",
                    self.sample_size,
                    self.sample_rate(),
                    self.channels,
                ).as_str());
            },
            Codec::AAC => panic!("Not implemented"),
            Codec::AALELC => panic!("Not implemented"),
        }

        match self.crypto {
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
    }

    pub fn analyse_setup(&self, setup_kd: &mut [key_data_t]) -> Result<(u16, u16, u16), Box<std::error::Error>> {
        unsafe {
            // get transport (port ...) info
            let transport_header = kd_lookup(&mut setup_kd[0], CString::new("Transport").unwrap().into_raw());

            if transport_header.is_null() {
                error!("no transport in response");
                panic!("no transport in response");
            }

            let mut audio_port: u16 = 0;
            let mut ctrl_port: u16 = 0;
            let mut time_port: u16 = 0;

            for token in CStr::from_ptr(transport_header).to_str()?.split(';') {
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
    }

    pub fn connect(&mut self, set_volume: bool) -> Result<(), Box<std::error::Error>> {
        {
            let status = self.status.lock().unwrap();

            if status.state != raop_states_s_RAOP_DOWN {
                return Ok(());
            }
        }

        let mut kd = [key_data_t { key: ptr::null_mut(), data: ptr::null_mut() }; 64];

        *self.ssrc.lock().unwrap() = random();
        *self.retransmit.lock().unwrap() = 0;

        {
            let mut sane = self.sane.lock().unwrap();

            sane.ctrl = 0;
            sane.time = 0;
            sane.audio.avail = 0;
            sane.audio.select = 0;
            sane.audio.send = 0;
        }

        let seed_sid: u32 = random();
        let seed_sci: u64 = random();

        let sid = format!("{:010}", seed_sid); // sprintf(sid, "%010lu", (long unsigned int) seed.sid);
        let sci = format!("{:016x}", seed_sci); // sprintf(sci, "%016llx", (long long int) seed.sci);

        // This block holds the rtsp_client lock
        {
            // RTSP misc setup
            let rtsp_client = self.rtsp_client.lock().unwrap();
            rtsp_client.add_exthds("Client-Instance", &sci)?;
            // FIXME:
            // if self.DACP_id[0] != 0 { rtspcl_add_eself.((*s_elient..cnew("DACP-ID").unwrap().into_raw(), self.DACP_id); }
            // if self.active_remote[0] != 0 { rtspclself.esel.f_ient((.s_elient.new("Active-Remote").unwrap().into_raw(), self.active_remote)?;

            rtsp_client.connect(self.local_addr.into(), self.remote_addr, self.rtsp_port, &sid)?;

            info!("local interface {}", rtsp_client.local_ip()?);

            // RTSP pairing verify for AppleTV
            if self.secret.is_some() {
                // FIXME: convert self.c_handle.secret to &str
                // rtsp_client.pair_verify(CStr::from_ptr(&(*self.c_handle).secret).to_str()?)?
                panic!("Not implemented");
            }

            // Send pubkey for MFi devices
            // FIXME:
            // if (strchr((*self.c_handle).et, '4')) rtsp_client.auth_setup()?;

            let mut sdp = format!(
                "v=0\r\no=iTunes {} 0 IN IP4 {}\r\ns=iTunes\r\nc=IN IP4 {}\r\nt=0 0\r\n",
                sid,
                rtsp_client.local_ip()?,
                self.remote_addr,
            );

            self.set_sdp(&mut sdp);

            // AppleTV expects now the timing port ot be opened BEFORE the setup message
            *self.rtp_time.lock().unwrap() = Some(UdpSocket::bind((self.local_addr, 0))?);
            let local_time_port = (*self.rtp_time.lock().unwrap()).as_ref().unwrap().local_addr()?.port();

            {
                let time_running = self.time_running.clone();
                let socket = self.rtp_time.clone();

                self.time_running.store(true, Ordering::Relaxed);
                *self.time_thread.lock().unwrap() = Some(thread::spawn(move || { _rtp_timing_thread(time_running, socket); }));
            }

            // RTSP ANNOUNCE
            if self.auth && self.crypto != Crypto::Clear {
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
            *self.rtp_ctrl.lock().unwrap() = Some(UdpSocket::bind((self.local_addr, 0))?);
            let local_ctrl_port = (*self.rtp_ctrl.lock().unwrap()).as_ref().unwrap().local_addr()?.port();

            *self.rtp_audio.lock().unwrap() = Some(UdpSocket::bind((self.local_addr, 0))?);
            let local_audio_port = (*self.rtp_audio.lock().unwrap()).as_ref().unwrap().local_addr()?.port();

            // RTSP SETUP : get all RTP destination ports
            let mut rtp_ports = rtp_port_s {
                time: sock_info_s { fd: -1, lport: local_time_port, rport: 0 },
                ctrl: sock_info_s { fd: -1, lport: local_ctrl_port, rport: 0 },
                audio: sock_info_s { fd: -1, lport: local_audio_port, rport: 0 },
            };
            rtsp_client.setup(&mut rtp_ports, &mut kd)?;
            let (remote_audio_port, remote_ctrl_port, remote_time_port) = self.analyse_setup(&mut kd)?;
            unsafe { free_kd(&mut kd[0]); }

            debug!("opened audio socket   l:{:05} r:{}", local_audio_port, remote_audio_port);
            debug!("opened timing socket  l:{:05} r:{}", local_time_port, remote_time_port);
            debug!("opened control socket l:{:05} r:{}", local_ctrl_port, remote_ctrl_port);

            (*self.rtp_audio.lock().unwrap()).as_ref().unwrap().connect((self.remote_addr, remote_audio_port))?;
            (*self.rtp_ctrl.lock().unwrap()).as_ref().unwrap().connect((self.remote_addr, remote_ctrl_port))?;

            {
                let status = self.status.lock().unwrap();
                rtsp_client.record(status.seq_number + 1, NTP2TS(safe_get_ntp(), self.sample_rate()) as u32, &mut kd)?;
            }
        }

        unsafe {
            let returned_latency = kd_lookup(&mut kd[0], CString::new("Audio-Latency").unwrap().into_raw());
            if !returned_latency.is_null() {
                let latency: u32 = CStr::from_ptr(returned_latency).to_str()?.trim().parse()?;
                let mut latency_frames = self.latency_frames.lock().unwrap();

                if latency > *latency_frames {
                    *latency_frames = latency;
                }
            }
            free_kd(&mut kd[0]);
        }

        {
            let client = self.clone();
            self.ctrl_running.store(true, Ordering::Relaxed);
            *self.ctrl_thread.lock().unwrap() = Some(thread::spawn(move || { _rtp_control_thread(client); }));
        }

        {
            // as connect might take time, state might already have been set
            let mut status = self.status.lock().unwrap();
            if status.state == raop_states_s_RAOP_DOWN { status.state = raop_states_s_RAOP_FLUSHED; }
        }

        if set_volume {
            self._set_volume()?;
        }

        Ok(())
    }

    fn _disconnect(&self, force: bool) -> Result<(), Box<std::error::Error>> {
        let mut status = self.status.lock().unwrap();

        if force == false && status.state == raop_states_s_RAOP_DOWN { return Ok(()); }

        status.state = raop_states_s_RAOP_DOWN;

        self._terminate_rtp()?;

        let rtsp_client = self.rtsp_client.lock().unwrap();
        let success1 = rtsp_client.flush(status.seq_number + 1, (status.head_ts + 1) as u32);
        let success2 = rtsp_client.disconnect();
        let success3 = rtsp_client.remove_all_exthds();

        success1?;
        success2?;
        success3?;

        Ok(())
    }

    pub fn disconnect(&self) -> Result<(), Box<std::error::Error>> {
        self._disconnect(false)
    }

    fn _send_sync(&self, status: &mut Status, first: bool) -> Result<(), Box<std::error::Error>> {
        unsafe {
            // do not send timesync on FLUSHED
            if status.state != raop_states_s_RAOP_STREAMING { return Ok(()); }

            let timestamp = status.head_ts;
            let now = TS2NTP(timestamp, self.sample_rate);

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
                rtp_timestamp_latency: ((timestamp - (*self.latency_frames.lock().unwrap() as u64)) as u32).to_be(),
            };

            trace!("[_send_sync] - aquiring ctrl socket");
            let socket = self.rtp_ctrl.lock().unwrap();
            trace!("[_send_sync] - got ctrl socket");
            let n = socket.as_ref().unwrap().send(any_as_u8_slice(&rsp))?;
            drop(socket);
            trace!("[_send_sync] - dropping ctrl socket");

            debug!("sync ntp:{}.{} (ts:{})", SEC(now), FRAC(now), status.head_ts);

            if n == 0 { info!("write, disconnected on the other end"); }
        }

        Ok(())
    }

    fn _send_audio(&self, status: &mut Status, packet: *mut rtp_audio_pkt_t, size: usize) -> Result<bool, Box<std::error::Error>> {
        unsafe {
            /*
            Do not send if audio port closed or we are not yet in streaming state. We
            might be just waiting for flush to happen in the case of a device taking a
            lot of time to connect, so avoid disturbing it with frames. Still, for sync
            reasons or when a starting time has been set, it's normal that the caller
            uses raopcld_accept_frames() and tries to send frames even before the
            connect has returned in case of multi-threaded application
            */
            // FIXME: if self.rtp_ports.audio.fd == -1  { return Ok(false); }
            if status.state != raop_states_s_RAOP_STREAMING { return Ok(false); }

            /*
            The audio socket is non blocking, so we can can wait socket availability
            but not too much. Half of the packet size if a good value. There is the
            backlog buffer to re-send packets if needed, so nothign is lost

            FIXME: This is no longer implemented :(
            */
            let socket = self.rtp_audio.lock().unwrap();
            let n = socket.as_ref().unwrap().send(any_as_u8_slice_len(&*packet, size)).unwrap();
            drop(socket);

            let mut ret = true;

            {
                let mut sane = self.sane.lock().unwrap();

                if n != size {
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

    fn _terminate_rtp(&self) -> Result<(), Box<std::error::Error>> {
        self.ctrl_running.store(false, Ordering::Relaxed);
        self.ctrl_thread.lock().unwrap().take().map(|ctrl_thread| ctrl_thread.join());

        self.time_running.store(false, Ordering::Relaxed);
        self.time_thread.lock().unwrap().take().map(|time_thread| time_thread.join());

        self.rtp_ctrl.lock().unwrap().take();
        self.rtp_time.lock().unwrap().take();
        self.rtp_audio.lock().unwrap().take();

        Ok(())
    }
}

impl Drop for RaopClient {
    fn drop(&mut self) {
        unsafe {
            self.disconnect().unwrap();

            let status = self.status.lock().unwrap();
            for i in 0..MAX_BACKLOG {
                free(status.backlog[i as usize].buffer as *mut std::ffi::c_void);
            }
        }
    }
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

extern fn _rtp_timing_thread(running: Arc<AtomicBool>, socket: Arc<Mutex<Option<UdpSocket>>>) {
    // FIXME: this should come from the UdpSocket
    let mut connected = false;

    while running.load(Ordering::Relaxed) {
        let socket_lock = socket.lock().unwrap();
        let socket = socket_lock.as_ref().unwrap();

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
        drop(socket_lock);

        if n == 0 {
            error!("read, disconnected on the other end");
            unsafe { usleep(100000); }
            continue;
        }

        thread::sleep(::std::time::Duration::from_secs(1));
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

// extern fn _rtp_control_thread(running: Arc<AtomicBool>, socket: Arc<Mutex<Option<UdpSocket>>>, sane: Arc<Mutex<raopcl_s__bindgen_ty_1>>) {
extern fn _rtp_control_thread(client: RaopClient) {
    // NOTE: socket _must_ be connected here
    {
        (*client.rtp_ctrl.lock().unwrap()).as_ref().unwrap().set_nonblocking(true).unwrap();
    }

    // Reuse this memory for receiving packet
    let mut lost = rtp_lost_pkt_t::new();

    while client.ctrl_running.load(Ordering::Relaxed) {
        trace!("[_rtp_control_thread] - aquiring ctrl socket");
        let socket_lock = client.rtp_ctrl.lock().unwrap();
        let socket = socket_lock.as_ref().unwrap();
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
                let mut sane = client.sane.lock().unwrap();

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
                let status = client.status.lock().unwrap();

                for i in 0..lost.n {
                    let index = ((lost.seq_number + i) % MAX_BACKLOG) as usize;

                    if status.backlog[index].seq_number == lost.seq_number + i {
                        let hdr = (status.backlog[index].buffer) as *mut rtp_header_t;

                        // packet have been released meanwhile, be extra cautious
                        if hdr.is_null() {
                            missed += 1;
                            continue;
                        }

                        unsafe {
                            (*hdr).proto = 0x80;
                            (*hdr).type_ = 0x56 | 0x80;
                            (*hdr).seq[0] = 0;
                            (*hdr).seq[1] = 1;
                        }

                        *client.retransmit.lock().unwrap() += 1;

                        socket.send(unsafe { any_as_u8_slice_len(&*hdr, size_of::<rtp_header_t>() + status.backlog[index].size as usize) }).unwrap();
                    } else {
                        warn!("lost packet out of backlog {}", lost.seq_number + i);
                    }
                }
            }

            debug!("retransmit packet sn:{} nb:{} (mis:{})", unsafe { lost.seq_number }, unsafe { lost.n }, missed);

            continue;
        }

        drop(socket);
        drop(socket_lock);
        trace!("[_rtp_control_thread] - dropping socket");

        {
            trace!("[_rtp_control_thread] - aquiring status");
            let mut status = client.status.lock().unwrap();
            trace!("[_rtp_control_thread] - got status");
            client._send_sync(&mut status, false).unwrap();
            trace!("[_rtp_control_thread] - dropping status");
        }

        thread::sleep(std::time::Duration::from_secs(1));
    }
}
