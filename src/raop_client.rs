use crate::bindings::{raopcl_s, raopcl_create, raop_states_s_RAOP_DOWN, raop_states_s_RAOP_FLUSHED, raop_states_s_RAOP_STREAMING, key_data_t, in_addr, raopcl_destroy, open_udp_socket, pthread_create, pthread_join, free_kd, get_ntp, kd_lookup, pthread_mutex_lock, pthread_mutex_unlock, rtp_header_t, rtp_audio_pkt_t, free, pcm_to_alac, pcm_to_alac_raw, malloc, sockaddr_in, sockaddr, AF_INET, rtp_sync_pkt_t, ntp_t, sendto, fd_set, lib_fd_zero, lib_fd_set, lib_fd_isset, timeval, close, select, sleep, usleep, recv, socklen_t, recvfrom};
use crate::rtsp_client::RTSPClient;

use std::ffi::{CStr, CString};

use std::ptr;
use std::net::Ipv4Addr;
use std::mem::size_of;

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

#[derive(Clone, Copy)]
pub enum Codec {
    PCM = 0,
    ALACRaw = 1,
    ALAC = 2,
    AAC = 3,
    AALELC = 4,
}

#[derive(Clone, Copy)]
pub enum Crypto {
    Clear = 0,
    RSA = 1,
    FairPlay = 2,
    MFiSAP = 3,
    FairPlaySAP = 4,
}

pub struct RaopClient {
    c_handle: *mut raopcl_s,

    codec: Codec,
    crypto: Crypto,

    rtsp_client: RTSPClient,
}

impl RaopClient {
    pub fn new(local: Ipv4Addr, codec: Codec, frame_length: u32, latency_frames: u32, crypto: Crypto, auth: bool, sample_rate: u32, sample_size: u32, channels: u8, volume: f32) -> Option<RaopClient> {
        let c_handle = unsafe { raopcl_create(local.into(), ptr::null_mut(), ptr::null_mut(), codec as u32, frame_length as i32, latency_frames as i32, crypto as u32, auth, ptr::null_mut(), ptr::null_mut(), ptr::null_mut(), sample_rate as i32, sample_size as i32, channels as i32, volume) };
        let rtsp_client = unsafe { RTSPClient::from_c_handle((*c_handle).rtspcl) };
        if c_handle.is_null() { None } else { Some(RaopClient { c_handle, codec, crypto, rtsp_client }) }
    }

    pub fn float_volume(vol: u8) -> f32 {
        if vol == 0 { return -144.0; }
        if vol >= 100 { return VOLUME_MAX; }

        VOLUME_MIN + ((VOLUME_MAX - VOLUME_MIN) * (vol as f32)) / 100.0
    }

    pub fn latency(&self) -> u32 {
        // Why do AirPlay devices use required latency + 11025?
        unsafe { (*self.c_handle).latency_frames + LATENCY_MIN }
    }

    pub fn sample_rate(&self) -> u32 {
        unsafe { (*self.c_handle).sample_rate as u32 }
    }

    pub fn is_playing(&self) -> bool {
        unsafe {
            let now_ts = NTP2TS(get_ntp(ptr::null_mut()), self.sample_rate());
            (*self.c_handle).pause_ts > 0 || now_ts < (*self.c_handle).head_ts + (self.latency() as u64)
        }
    }

    pub fn accept_frames(&self) -> Result<bool, Box<std::error::Error>> {
        let mut first_pkt = false;
        let mut now_ts: u64;

        unsafe {
            pthread_mutex_lock(&mut (*self.c_handle).mutex);

            // a flushing is pending
            if (*self.c_handle).flushing {
                let now = get_ntp(ptr::null_mut());

                now_ts = NTP2TS(now, self.sample_rate());

                // Not flushed yet, but we have time to wait, so pretend we are full
                if (*self.c_handle).state != raop_states_s_RAOP_FLUSHED && (!(*self.c_handle).start_ts > 0 || (*self.c_handle).start_ts > now_ts + self.latency() as u64) {
                    pthread_mutex_unlock(&mut (*self.c_handle).mutex);
                    return Ok(false);
                }

                // move to streaming only when really flushed - not when timedout
                if (*self.c_handle).state == raop_states_s_RAOP_FLUSHED {
                    (*self.c_handle).first_pkt = true;
                    first_pkt = true;
                    info!("begining to stream hts:{} n:{}.{}", (*self.c_handle).head_ts, SEC(now), FRAC(now));
                    (*self.c_handle).state = raop_states_s_RAOP_STREAMING;
                }

                // unpausing ...
                if (*self.c_handle).pause_ts == 0 {
                    (*self.c_handle).head_ts = if (*self.c_handle).start_ts > 0 { (*self.c_handle).start_ts } else { now_ts };
                    (*self.c_handle).first_ts = (*self.c_handle).head_ts;
                    if first_pkt { self._send_sync(true)?; }
                    info!("restarting w/o pause n:{}.{}, hts:{}", SEC(now), FRAC(now), (*self.c_handle).head_ts);
                } else {
                    let mut n: u16;
                    let mut i: u16;
                    let chunks = (self.latency() / (*self.c_handle).chunk_len as u32) as u16;

                    // if un-pausing w/o start_time, can anticipate as we have buffer
                    (*self.c_handle).first_ts = if (*self.c_handle).start_ts > 0 { (*self.c_handle).start_ts } else { now_ts - self.latency() as u64 };

                    // last head_ts shall be first + raopcl_latency - chunk_len
                    (*self.c_handle).head_ts = (*self.c_handle).first_ts - (*self.c_handle).chunk_len as u64;

                    if first_pkt { self._send_sync(true)?; }

                    info!("restarting w/ pause n:{}.{}, hts:{} (re-send: {})", SEC(now), FRAC(now), (*self.c_handle).head_ts, chunks);

                    // search pause_ts in backlog, it should be backward, not too far
                    n = (*self.c_handle).seq_number;
                    i = 0;
                    while i < MAX_BACKLOG && (*self.c_handle).backlog[(n % MAX_BACKLOG) as usize].timestamp > (*self.c_handle).pause_ts {
                        i += 1;
                        n -= 1;
                    }

                    // the resend shall go up to (including) pause_ts
                    n = (n - chunks + 1) % MAX_BACKLOG;

                    // re-send old packets
                    i = 0;
                    while i < chunks {
                        let index = ((n + i) % MAX_BACKLOG) as usize;

                        if (*self.c_handle).backlog[index].buffer.is_null() { continue; }

                        (*self.c_handle).seq_number += 1;

                        let mut packet = (*self.c_handle).backlog[index].buffer.offset(size_of::<rtp_header_t>() as isize) as *mut rtp_audio_pkt_t;
                        (*packet).hdr.seq[0] = (((*self.c_handle).seq_number >> 8) & 0xff) as u8;
                        (*packet).hdr.seq[1] = ((*self.c_handle).seq_number & 0xff) as u8;
                        (*packet).timestamp = ((*self.c_handle).head_ts as u32).to_be();
                        (*packet).hdr.type_ = 0x60 | (if (*self.c_handle).first_pkt { 0x80 } else { 0 });
                        (*self.c_handle).first_pkt = false;

                        // then replace packets in backlog in case
                        let reindex = ((*self.c_handle).seq_number % MAX_BACKLOG) as usize;

                        (*self.c_handle).backlog[reindex].seq_number = (*self.c_handle).seq_number;
                        (*self.c_handle).backlog[reindex].timestamp = (*self.c_handle).head_ts;
                        if !(*self.c_handle).backlog[reindex].buffer.is_null() { free((*self.c_handle).backlog[reindex].buffer as *mut std::ffi::c_void); }
                        (*self.c_handle).backlog[reindex].buffer = (*self.c_handle).backlog[index].buffer;
                        (*self.c_handle).backlog[reindex].size = (*self.c_handle).backlog[index].size;
                        (*self.c_handle).backlog[index].buffer = ptr::null_mut();

                        (*self.c_handle).head_ts += (*self.c_handle).chunk_len as u64;

                        self._send_audio(packet, (*self.c_handle).backlog[reindex].size as usize)?;

                        i += 1;
                    }

                    debug!("finished resend {}", i);
                }

                (*self.c_handle).pause_ts = 0;
                (*self.c_handle).start_ts = 0;
                (*self.c_handle).flushing = false;
            }

            // when paused, fix "now" at the time when it was paused.
            if (*self.c_handle).pause_ts > 0 {
                now_ts = (*self.c_handle).pause_ts;
            } else {
                now_ts = NTP2TS(get_ntp(ptr::null_mut()), self.sample_rate());
            }

            let accept = now_ts >= (*self.c_handle).head_ts + ((*self.c_handle).chunk_len) as u64;

            pthread_mutex_unlock(&mut (*self.c_handle).mutex);

            return Ok(accept);
        }
    }

    pub fn send_chunk(&self, sample: &mut [u8], frames: usize, playtime: &mut u64) -> Result<(), Box<std::error::Error>> {
        unsafe {
            let now = get_ntp(ptr::null_mut());

            pthread_mutex_lock(&mut (*self.c_handle).mutex);

            /*
            Move to streaming state only when really flushed. In most cases, this is
            done by the raopcl_accept_frames function, except when a player takes too
            long to flush (JBL OnBeat) and we have to "fake" accepting frames
            */
            if (*self.c_handle).state == raop_states_s_RAOP_FLUSHED {
                (*self.c_handle).first_pkt = true;
                info!("begining to stream (LATE) hts:{} n:{}.{}", (*self.c_handle).head_ts, SEC(now), FRAC(now));
                (*self.c_handle).state = raop_states_s_RAOP_STREAMING;
                self._send_sync(true)?;
            }

            let mut encoded: *mut u8 = ptr::null_mut();
            let mut size: i32 = 0;

            match self.codec {
                Codec::ALAC => {
                    pcm_to_alac((*self.c_handle).alac_codec, &mut (*sample)[0], frames as i32, &mut encoded, &mut size);
                },
                Codec::ALACRaw => {
                    pcm_to_alac_raw(&mut (*sample)[0], frames as i32, &mut encoded, &mut size, (*self.c_handle).chunk_len);
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
                pthread_mutex_unlock(&mut (*self.c_handle).mutex);
                free(encoded as *mut std::ffi::c_void);
                error!("cannot allocate buffer");
                panic!("Cannot allocate buffer");
            }

            *playtime = TS2NTP((*self.c_handle).head_ts + self.latency() as u64, self.sample_rate());

            trace!("sending audio ts:{} (pt:{}.{} now:{}) ", (*self.c_handle).head_ts, SEC(*playtime), FRAC(*playtime), get_ntp(ptr::null_mut()));

            (*self.c_handle).seq_number += 1;

            // packet is after re-transmit header
            // packet = (rtp_audio_pkt_t *) (buffer + sizeof(rtp_header_t));
            let packet = buffer.offset(size_of::<rtp_header_t>() as isize) as *mut rtp_audio_pkt_t;
            (*packet).hdr.proto = 0x80;
            (*packet).hdr.type_ = 0x60 | (if (*self.c_handle).first_pkt { 0x80 } else { 0 });
            (*self.c_handle).first_pkt = false;
            (*packet).hdr.seq[0] = (((*self.c_handle).seq_number >> 8) & 0xff) as u8;
            (*packet).hdr.seq[1] = ((*self.c_handle).seq_number & 0xff) as u8;
            (*packet).timestamp = ((*self.c_handle).head_ts as u32).to_be();
            (*packet).ssrc = ((*self.c_handle).ssrc as u32).to_be();

            buffer.offset((size_of::<rtp_header_t>() + size_of::<rtp_audio_pkt_t>()) as isize).copy_from(encoded, size as usize);

            // with newer airport express, don't use encryption (??)
            if (*self.c_handle).encrypt {
                panic!("Not implemented");
                // raopcl_encrypt(p, (u8_t*) packet + sizeof(rtp_audio_pkt_t), size);
            }

            let n = ((*self.c_handle).seq_number % MAX_BACKLOG) as usize;
            (*self.c_handle).backlog[n].seq_number = (*self.c_handle).seq_number;
            (*self.c_handle).backlog[n].timestamp = (*self.c_handle).head_ts;
            if !(*self.c_handle).backlog[n].buffer.is_null() { free((*self.c_handle).backlog[n].buffer as *mut std::ffi::c_void); }
            (*self.c_handle).backlog[n].buffer = buffer;
            (*self.c_handle).backlog[n].size = (size_of::<rtp_audio_pkt_t>() as i32) + size;

            (*self.c_handle).head_ts += (*self.c_handle).chunk_len as u64;

            self._send_audio(packet, size_of::<rtp_audio_pkt_t>() + (size as usize))?;

            pthread_mutex_unlock(&mut (*self.c_handle).mutex);

            if NTP2MS(*playtime) % 10000 < 8 {
                info!("check n:{} p:{} ts:{} sn:{}\n               retr: {}, avail: {}, send: {}, select: {})",
                    MSEC(now), MSEC(*playtime), (*self.c_handle).head_ts, (*self.c_handle).seq_number,
                    (*self.c_handle).retransmit, (*self.c_handle).sane.audio.avail, (*self.c_handle).sane.audio.send,
                    (*self.c_handle).sane.audio.select);
            }

            free(encoded as *mut std::ffi::c_void);
        }

        Ok(())
    }

    fn set_volume(&self, vol: f32) -> Result<(), Box<std::error::Error>> {
        if (vol < -30.0 || vol > 0.0) && vol != -144.0 { panic!("Invalid volume"); }
        unsafe { (*self.c_handle).volume = vol; }

        unsafe {
            if (*self.c_handle).rtspcl.is_null() || (*self.c_handle).state < raop_states_s_RAOP_FLUSHED { return Ok(()); }
        }

        let parameter = format!("volume: {}\r\n", vol);
        self.rtsp_client.set_parameter(&parameter)?;

        Ok(())
    }

    pub fn set_sdp(&self, sdp: &mut String) {
        match self.codec {
            Codec::ALACRaw => {
                sdp.push_str(format!(
                    "m=audio 0 RTP/AVP 96\r\na=rtpmap:96 AppleLossless\r\na=fmtp:96 {}d 0 {} 40 10 14 {} 255 0 0 {}\r\n",
                    unsafe { (*self.c_handle).chunk_len },
                    unsafe { (*self.c_handle).sample_size },
                    unsafe { (*self.c_handle).channels },
                    self.sample_rate(),
                ).as_str());
            },
            Codec::ALAC => {
                sdp.push_str(format!(
                    "m=audio 0 RTP/AVP 96\r\na=rtpmap:96 AppleLossless\r\na=fmtp:96 {}d 0 {} 40 10 14 {} 255 0 0 {}\r\n",
                    unsafe { (*self.c_handle).chunk_len },
                    unsafe { (*self.c_handle).sample_size },
                    unsafe { (*self.c_handle).channels },
                    self.sample_rate(),
                ).as_str());
            },
            Codec::PCM => {
                sdp.push_str(format!(
                    "m=audio 0 RTP/AVP 96\r\na=rtpmap:96 L{}/{}/{}\r\n",
                    unsafe { (*self.c_handle).sample_size },
                    self.sample_rate(),
                    unsafe { (*self.c_handle).channels },
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

    pub fn analyse_setup(&self, setup_kd: &mut [key_data_t]) -> Result<(), Box<std::error::Error>> {
        unsafe {
            // get transport (port ...) info
            let transport_header = kd_lookup(&mut setup_kd[0], CString::new("Transport").unwrap().into_raw());

            if transport_header.is_null() {
                error!("no transport in response");
                panic!("no transport in response");
            }

            for token in CStr::from_ptr(transport_header).to_str()?.split(';') {
                match token.split('=').collect::<Vec<&str>>().as_slice() {
                    ["server_port", port] => (*self.c_handle).rtp_ports.audio.rport = port.parse()?,
                    ["control_port", port] => (*self.c_handle).rtp_ports.ctrl.rport = port.parse()?,
                    ["timing_port", port] => (*self.c_handle).rtp_ports.time.rport = port.parse()?,
                    _ => {},
                }
            }

            if !(*self.c_handle).rtp_ports.audio.rport == 0 || (*self.c_handle).rtp_ports.ctrl.rport == 0 {
                error!("missing a RTP port in response");
                panic!("missing a RTP port in response");
            }

            if !(*self.c_handle).rtp_ports.time.rport == 0 {
                info!("missing timing port, will get it later");
            }
        }

        Ok(())
    }

    pub fn connect(&mut self, host: Ipv4Addr, destport: u16, set_volume: bool) -> Result<(), Box<std::error::Error>> {
        unsafe {
            if (*self.c_handle).state != raop_states_s_RAOP_DOWN {
                return Ok(());
            }

            let mut kd = [key_data_t { key: ptr::null_mut(), data: ptr::null_mut() }; 64];

            if host != Ipv4Addr::UNSPECIFIED { (*self.c_handle).host_addr.s_addr = in_addr::from(host).s_addr; }
            if destport != 0 { (*self.c_handle).rtsp_port = destport; }

            (*self.c_handle).ssrc = random();

            (*self.c_handle).encrypt = (*self.c_handle).crypto != Crypto::Clear as u32;
            (*self.c_handle).sane.ctrl = 0;
            (*self.c_handle).sane.time = 0;
            (*self.c_handle).sane.audio.avail = 0;
            (*self.c_handle).sane.audio.select = 0;
            (*self.c_handle).sane.audio.send = 0;
            (*self.c_handle).retransmit = 0;

            let seed_sid: u32 = random();
            let seed_sci: u64 = random();

            let sid = format!("{:010}", seed_sid); // sprintf(sid, "%010lu", (long unsigned int) seed.sid);
            let sci = format!("{:016x}", seed_sci); // sprintf(sci, "%016llx", (long long int) seed.sci);

            // RTSP misc setup
            self.rtsp_client.add_exthds("Client-Instance", &sci)?;
            // FIXME:
            // if (*self.c_handle).DACP_id[0] != 0 { rtspcl_add_eself.((*s_elient..cnew("DACP-ID").unwrap().into_raw(), (*self.c_handle).DACP_id); }
            // if (*self.c_handle).active_remote[0] != 0 { rtspclself.esel.f_ient((.s_elient.new("Active-Remote").unwrap().into_raw(), (*self.c_handle).active_remote)?;

            self.rtsp_client.connect((*self.c_handle).local_addr.into(), host, destport, &sid)?;

            info!("local interface {}", self.rtsp_client.local_ip()?);

            // RTSP pairing verify for AppleTV
            if (*self.c_handle).secret[0] != 0 {
                // FIXME: convert self.c_handle.secret to &str
                // self.rtsp_client.pair_verify(CStr::from_ptr(&(*self.c_handle).secret).to_str()?)?
                panic!("Not implemented");
            }

            // Send pubkey for MFi devices
            // FIXME:
            // if (strchr((*self.c_handle).et, '4')) self.rtsp_client.auth_setup()?;

            let mut sdp = format!(
                "v=0\r\no=iTunes {} 0 IN IP4 {}\r\ns=iTunes\r\nc=IN IP4 {}\r\nt=0 0\r\n",
                sid,
                self.rtsp_client.local_ip()?,
                host,
            );

            self.set_sdp(&mut sdp);

            // AppleTV expects now the timing port ot be opened BEFORE the setup message
            (*self.c_handle).rtp_ports.time.lport = 0;
            (*self.c_handle).rtp_ports.time.rport = 0;
            (*self.c_handle).rtp_ports.time.fd = open_udp_socket((*self.c_handle).local_addr, &mut (*self.c_handle).rtp_ports.time.lport, true);
            if (*self.c_handle).rtp_ports.time.fd == -1 { panic!("Failed to open UDP socket"); }
            (*self.c_handle).time_running = true;
            pthread_create(&mut (*self.c_handle).time_thread, ptr::null(), Some(_rtp_timing_thread), self.c_handle as *mut std::ffi::c_void);

            // RTSP ANNOUNCE
            if (*self.c_handle).auth && (*self.c_handle).crypto != 0 {
                panic!("Not implemented");
                // let seed_sac: [u8; 16] = random();
                // base64_encode(&seed.sac, 16, &sac);
                // remove_char_from_string(sac, '=');
                // self.rtsp_client.add_exthds("Apple-Challenge", &sac)?;
                // self.rtsp_client.announce_sdp(&sdp)?;
                // self.rtsp_client.mark_del_exthds("Apple-Challenge")?;
            } else {
                self.rtsp_client.announce_sdp(&sdp)?;
            }

            // open RTP sockets, need local ports here before sending SETUP
            (*self.c_handle).rtp_ports.ctrl.lport = 0;
            (*self.c_handle).rtp_ports.audio.lport = 0;
            (*self.c_handle).rtp_ports.ctrl.fd = open_udp_socket((*self.c_handle).local_addr, &mut (*self.c_handle).rtp_ports.ctrl.lport, true);
            if (*self.c_handle).rtp_ports.ctrl.fd == -1 { panic!("Failed to open UDP socket"); }
            (*self.c_handle).rtp_ports.audio.fd = open_udp_socket((*self.c_handle).local_addr, &mut (*self.c_handle).rtp_ports.audio.lport, false);
            if (*self.c_handle).rtp_ports.audio.fd == -1 { panic!("Failed to open UDP socket"); }

            // RTSP SETUP : get all RTP destination ports
            self.rtsp_client.setup(&mut (*self.c_handle).rtp_ports, &mut kd)?;
            self.analyse_setup(&mut kd)?;
            free_kd(&mut kd[0]);

            debug!("opened audio socket   l:{:05} r:{}", (*self.c_handle).rtp_ports.audio.lport, (*self.c_handle).rtp_ports.audio.rport);
            debug!("opened timing socket  l:{:05} r:{}", (*self.c_handle).rtp_ports.time.lport, (*self.c_handle).rtp_ports.time.rport);
            debug!("opened control socket l:{:05} r:{}", (*self.c_handle).rtp_ports.ctrl.lport, (*self.c_handle).rtp_ports.ctrl.rport);

            self.rtsp_client.record((*self.c_handle).seq_number + 1, NTP2TS(get_ntp(ptr::null_mut()), self.sample_rate()) as u32, &mut kd)?;

            let returned_latency = kd_lookup(&mut kd[0], CString::new("Audio-Latency").unwrap().into_raw());
            if !returned_latency.is_null() {
                let latency: u32 = CStr::from_ptr(returned_latency).to_str()?.trim().parse()?;

                if latency > (*self.c_handle).latency_frames {
                    (*self.c_handle).latency_frames = latency;
                }
            }
            free_kd(&mut kd[0]);

            (*self.c_handle).ctrl_running = true;
            pthread_create(&mut (*self.c_handle).ctrl_thread, ptr::null(), Some(_rtp_control_thread), (self as *mut RaopClient) as *mut std::ffi::c_void);

            pthread_mutex_lock(&mut (*self.c_handle).mutex);
            // as connect might take time, state might already have been set
            if (*self.c_handle).state == raop_states_s_RAOP_DOWN { (*self.c_handle).state = raop_states_s_RAOP_FLUSHED; }
            pthread_mutex_unlock(&mut (*self.c_handle).mutex);

            if set_volume {
                self.set_volume((*self.c_handle).volume)?;
            }
        }

        Ok(())
    }

    fn _disconnect(&self, force: bool) -> Result<(), Box<std::error::Error>> {
        unsafe {
            if force == false && (*self.c_handle).state == raop_states_s_RAOP_DOWN { return Ok(()); }

            pthread_mutex_lock(&mut (*self.c_handle).mutex);
            (*self.c_handle).state = raop_states_s_RAOP_DOWN;
            pthread_mutex_unlock(&mut (*self.c_handle).mutex);

            self._terminate_rtp()?;

            let success1 = self.rtsp_client.flush((*self.c_handle).seq_number + 1, ((*self.c_handle).head_ts + 1) as u32);
            let success2 = self.rtsp_client.disconnect();
            let success3 = self.rtsp_client.remove_all_exthds();

            success1?;
            success2?;
            success3?;
        }

        Ok(())
    }

    pub fn disconnect(&self) -> Result<(), Box<std::error::Error>> {
        self._disconnect(false)
    }

    fn _send_sync(&self, first: bool) -> Result<(), Box<std::error::Error>> {
        unsafe {
            let addr = sockaddr_in {
                sin_family: AF_INET as u8,
                sin_addr: (*self.c_handle).host_addr,
                sin_port: (*self.c_handle).rtp_ports.ctrl.rport.to_be(),
                sin_len: 0,
                sin_zero: [0; 8],
            };

            // do not send timesync on FLUSHED
            if (*self.c_handle).state != raop_states_s_RAOP_STREAMING { return Ok(()); }

            let mut rsp = rtp_sync_pkt_t {
                hdr: rtp_header_t {
                    proto: 0x80 | if first { 0x10 } else { 0x00 },
                    type_: 0x54 | 0x80,
                    // seems that seq=7 shall be forced
                    seq: [0, 7],
                },
                rtp_timestamp_latency: 0,
                curr_time: ntp_t {
                    seconds: 0,
                    fraction: 0,
                },
                rtp_timestamp: 0,
            };

            // first sync is called with mutex locked, so don't block
            if !first { pthread_mutex_lock(&mut (*self.c_handle).mutex); }

            let timestamp = (*self.c_handle).head_ts;
            let now = TS2NTP(timestamp, (*self.c_handle).sample_rate as u32);

            // set the NTP time in network order
            rsp.curr_time.seconds = SEC(now).to_be();
            rsp.curr_time.fraction = FRAC(now).to_be();

            // The DAC time is synchronized with gettime_ms(), minus the latency.
            rsp.rtp_timestamp = (timestamp as u32).to_be();
            rsp.rtp_timestamp_latency = ((timestamp - ((*self.c_handle).latency_frames as u64)) as u32).to_be();

            let n = sendto((*self.c_handle).rtp_ports.ctrl.fd, ((&rsp) as *const rtp_sync_pkt_t) as *const std::ffi::c_void, size_of::<rtp_sync_pkt_t>(), 0, (&addr as *const sockaddr_in) as *const sockaddr, size_of::<sockaddr_in>() as u32);

            if !first { pthread_mutex_unlock(&mut (*self.c_handle).mutex); }

            debug!("sync ntp:{}.{} (ts:{})", SEC(now), FRAC(now), (*self.c_handle).head_ts);

            if n < 0 { error!("write error"/* FIXME: , strerror(errno)*/); }
            if n == 0 { info!("write, disconnected on the other end"); }
        }

        Ok(())
    }

    fn _send_audio(&self, packet: *mut rtp_audio_pkt_t, size: usize) -> Result<bool, Box<std::error::Error>> {
        unsafe {
            /*
            Do not send if audio port closed or we are not yet in streaming state. We
            might be just waiting for flush to happen in the case of a device taking a
            lot of time to connect, so avoid disturbing it with frames. Still, for sync
            reasons or when a starting time has been set, it's normal that the caller
            uses raopcld_accept_frames() and tries to send frames even before the
            connect has returned in case of multi-threaded application
            */
            if (*self.c_handle).rtp_ports.audio.fd == -1 || (*self.c_handle).state != raop_states_s_RAOP_STREAMING { return Ok(false); }

            let addr = sockaddr_in {
                sin_family: AF_INET as u8,
                sin_addr: (*self.c_handle).host_addr,
                sin_port: (*self.c_handle).rtp_ports.audio.rport.to_be(),
                sin_len: 0,
                sin_zero: [0; 8],
            };

            let mut wfds = fd_set { fds_bits: [0; 32usize] };

            lib_fd_zero(&mut wfds);
            lib_fd_set((*self.c_handle).rtp_ports.audio.fd, &mut wfds);

            /*
            The audio socket is non blocking, so we can can wait socket availability
            but not too much. Half of the packet size if a good value. There is the
            backlog buffer to re-send packets if needed, so nothign is lost
            */
            let mut timeout = timeval {
                tv_sec: 0,
                tv_usec: ((((*self.c_handle).chunk_len as u64) * 1000000) / (((*self.c_handle).sample_rate as u64) * 2)) as i32,
            };

            if select((*self.c_handle).rtp_ports.audio.fd + 1, ptr::null_mut(), &mut wfds, ptr::null_mut(), &mut timeout) == -1 {
                error!("audio socket closed");
                (*self.c_handle).sane.audio.select += 1;
            } else {
                (*self.c_handle).sane.audio.select = 0;
            }

            let mut ret = true;

            if lib_fd_isset((*self.c_handle).rtp_ports.audio.fd, &mut wfds) {
                let n = sendto((*self.c_handle).rtp_ports.audio.fd, (packet) as *const std::ffi::c_void, size, 0, (&addr as *const sockaddr_in) as *const sockaddr, size_of::<sockaddr_in>() as u32);

                if n != size as isize {
                    debug!("error sending audio packet");
                    ret = false;
                    (*self.c_handle).sane.audio.send += 1;
                } else {
                    (*self.c_handle).sane.audio.send = 0;
                }

                (*self.c_handle).sane.audio.avail = 0;
            } else {
                debug!("audio socket unavailable");
                ret = false;
                (*self.c_handle).sane.audio.avail += 1;
            }

            return Ok(ret);
        }
    }

    fn _terminate_rtp(&self) -> Result<(), Box<std::error::Error>> {
        unsafe {
            (*self.c_handle).ctrl_running = false;
            pthread_join((*self.c_handle).ctrl_thread, ptr::null_mut());

            (*self.c_handle).time_running = false;
            pthread_join((*self.c_handle).time_thread, ptr::null_mut());

            if (*self.c_handle).rtp_ports.ctrl.fd != -1 {
                close((*self.c_handle).rtp_ports.ctrl.fd);
                (*self.c_handle).rtp_ports.ctrl.fd = -1;
            }

            if (*self.c_handle).rtp_ports.time.fd != -1 {
                close((*self.c_handle).rtp_ports.time.fd);
                (*self.c_handle).rtp_ports.time.fd = -1;
            }

            if (*self.c_handle).rtp_ports.audio.fd != -1 {
                close((*self.c_handle).rtp_ports.audio.fd);
                (*self.c_handle).rtp_ports.audio.fd = -1;
            }
        }

        Ok(())
    }
}

impl Drop for RaopClient {
    fn drop(&mut self) {
        unsafe { raopcl_destroy(self.c_handle); }
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

extern fn _rtp_timing_thread(args: *mut std::ffi::c_void) -> *mut std::ffi::c_void {
    unsafe {
        let raopcld: *mut raopcl_s = args as *mut raopcl_s;
        let mut addr = sockaddr_in {
            sin_family: AF_INET as u8,
            sin_addr: (*raopcld).host_addr,
            sin_port: (*raopcld).rtp_ports.time.rport.to_be(),
            sin_len: 0,
            sin_zero: [0; 8],
        };

        while (*raopcld).time_running {
            let mut req = rtp_time_pkt_t::new();
            let mut timeout = timeval { tv_sec: 1, tv_usec: 0 };

            let mut n: i32;
            let mut rfds = fd_set { fds_bits: [0; 32usize] };

            lib_fd_zero(&mut rfds);
            lib_fd_set((*raopcld).rtp_ports.time.fd, &mut rfds);

            n = select((*raopcld).rtp_ports.time.fd + 1, &mut rfds, ptr::null_mut(), ptr::null_mut(), &mut timeout);
            if n == -1 {
                error!("raopcl_time_connect: socket closed on the other end");
                usleep(100000);
                continue;
            }

            if !lib_fd_isset((*raopcld).rtp_ports.time.fd, &mut rfds) {
                continue;
            }

            if addr.sin_port > 0 {
                n = recv((*raopcld).rtp_ports.time.fd, ((&mut req) as *mut rtp_time_pkt_t) as *mut std::ffi::c_void, size_of::<rtp_time_pkt_t>(), 0) as i32;
            } else {
                let mut client = sockaddr_in {
                    sin_family: 0,
                    sin_addr: in_addr { s_addr: 0 },
                    sin_port: 0,
                    sin_len: 0,
                    sin_zero: [0; 8],
                };

                let mut len = size_of::<sockaddr_in>() as socklen_t;
                n = recvfrom((*raopcld).rtp_ports.time.fd, ((&mut req) as *mut rtp_time_pkt_t) as *mut std::ffi::c_void, size_of::<rtp_time_pkt_t>(), 0, (((&mut client) as *mut sockaddr_in) as *mut std::ffi::c_void) as *mut sockaddr, &mut len) as i32;
                addr.sin_port = client.sin_port;
                debug!("NTP remote port: {}", u16::from_be(addr.sin_port));
            }

            if n > 0 {
                let mut rsp = rtp_time_pkt_t::new();

                rsp.hdr = req.hdr;
                rsp.hdr.type_ = 0x53 | 0x80;
                // just copy the request header or set seq=7 and timestamp=0
                rsp.ref_time = req.send_time;

                // transform timeval into NTP and set network order
                get_ntp(&mut rsp.recv_time);

                rsp.recv_time.seconds = rsp.recv_time.seconds.to_be();
                rsp.recv_time.fraction = rsp.recv_time.fraction.to_be();
                rsp.send_time = rsp.recv_time; // might need to add a few fraction ?

                n = sendto((*raopcld).rtp_ports.time.fd, ((&rsp) as *const rtp_time_pkt_t) as *const std::ffi::c_void, size_of::<rtp_time_pkt_t>(), 0, (&addr as *const sockaddr_in) as *const sockaddr, size_of::<sockaddr_in>() as u32) as i32;

                if n != size_of::<rtp_time_pkt_t>() as i32 {
                    error!("error responding to sync");
                }

                debug!("NTP sync: {}.{} (ref {}.{})", u32::from_be(rsp.send_time.seconds), u32::from_be(rsp.send_time.fraction),
                                                      u32::from_be(rsp.ref_time.seconds), u32::from_be(rsp.ref_time.fraction));

            }

            if n < 0 {
                error!("read error"/* FIXME: , strerror(errno)*/);
            }

            if n == 0 {
                error!("read, disconnected on the other end");
                usleep(100000);
                continue;
            }
        }
    }

    ptr::null_mut()
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

extern fn _rtp_control_thread(args: *mut std::ffi::c_void) -> *mut std::ffi::c_void {
    unsafe {
        let client: *mut RaopClient = args as *mut RaopClient;
        let raopcld: *mut raopcl_s = (*client).c_handle;

        while (*raopcld).ctrl_running {
            let mut timeout = timeval { tv_sec: 1, tv_usec: 0 };
            let mut rfds = fd_set { fds_bits: [0; 32usize] };

            lib_fd_zero(&mut rfds);
            lib_fd_set((*raopcld).rtp_ports.ctrl.fd, &mut rfds);

            if select((*raopcld).rtp_ports.ctrl.fd + 1, &mut rfds, ptr::null_mut(), ptr::null_mut(), &mut timeout) == -1 {
                if (*raopcld).ctrl_running {
                    error!("control socket closed");
                    (*raopcld).sane.ctrl += 1;
                    sleep(1);
                }
                continue;
            }

            if lib_fd_isset((*raopcld).rtp_ports.ctrl.fd, &mut rfds) {
                let mut lost = rtp_lost_pkt_t::new();
                // int i, n, missed;

                let n = recv((*raopcld).rtp_ports.ctrl.fd, ((&mut lost) as *mut rtp_lost_pkt_t) as *mut std::ffi::c_void, size_of::<rtp_lost_pkt_t>(), 0);

                if n < 0 { continue; }

                lost.seq_number = u16::from_be(lost.seq_number);
                lost.n = u16::from_be(lost.n);

                if n != size_of::<rtp_lost_pkt_t>() as isize {
                    error!("error in received request sn:{} n:{} (recv:{})",
                            lost.seq_number, lost.n, n);
                    lost.n = 0;
                    lost.seq_number = 0;
                    (*raopcld).sane.ctrl += 1;
                } else {
                    (*raopcld).sane.ctrl = 0;
                }

                pthread_mutex_lock(&mut (*raopcld).mutex);

                let mut missed: i32 = 0;
                for i in 0..lost.n {
                    let index = ((lost.seq_number + i) % MAX_BACKLOG) as usize;

                    if (*raopcld).backlog[index].seq_number == lost.seq_number + i {
                        // struct sockaddr_in addr;
                        let hdr = ((*raopcld).backlog[index].buffer) as *mut rtp_header_t;

                        // packet have been released meanwhile, be extra cautious
                        if hdr.is_null() { continue; }

                        (*hdr).proto = 0x80;
                        (*hdr).type_ = 0x56 | 0x80;
                        (*hdr).seq[0] = 0;
                        (*hdr).seq[1] = 1;

                        let mut addr = sockaddr_in {
                            sin_family: AF_INET as u8,
                            sin_addr: (*raopcld).host_addr,
                            sin_port: (*raopcld).rtp_ports.ctrl.rport.to_be(),
                            sin_len: 0,
                            sin_zero: [0; 8],
                        };

                        (*raopcld).retransmit += 1;

                        let n = sendto((*raopcld).rtp_ports.ctrl.fd, hdr as *mut std::ffi::c_void,
                                size_of::<rtp_header_t>() + (*raopcld).backlog[index].size as usize,
                                0, (&addr as *const sockaddr_in) as *const sockaddr, size_of::<sockaddr_in>() as u32);

                        if n == -1 {
                            warn!("error resending lost packet sn:{} (n:{})", lost.seq_number + i, n);
                        }
                    }
                    else {
                        warn!("lost packet out of backlog {}", lost.seq_number + i);
                    }
                }

                pthread_mutex_unlock(&mut (*raopcld).mutex);

                debug!("retransmit packet sn:{} nb:{} (mis:{})", lost.seq_number, lost.n, missed);

                continue;
            }

            (*client)._send_sync(false);
        }
    }

    return ptr::null_mut();
}
