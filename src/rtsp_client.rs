use crate::bindings::{rtspcl_s, rtspcl_create, rtspcl_disconnect, rtspcl_auth_setup, rtspcl_remove_all_exthds, rtspcl_add_exthds, rtspcl_mark_del_exthds, rtspcl_local_ip, rtspcl_destroy};
use crate::bindings::{open_tcp_socket, get_tcp_connect_by_host, getsockname, in_addr, sockaddr, sockaddr_in, send, recv, read_line, malloc, memcpy, strcpy, free};
use crate::bindings::{ed25519_public_key_size, ed25519_secret_key_size, ed25519_private_key_size, ed25519_signature_size, ed25519_CreateKeyPair, curve25519_dh_CalculatePublicKey, curve25519_dh_CreateSharedKey, ed25519_SignMessage};
use crate::bindings::{CTR_BIG_ENDIAN, aes_ctr_context, aes_ctr_init, aes_ctr_encrypt};

use openssl_sys::{SHA512_CTX, SHA512_Init, SHA512_Update, SHA512_Final};

use std::ffi::{CStr, CString, c_void};
use std::io::Write;
use std::mem::size_of;
use std::net::Ipv4Addr;
use std::ptr;
use std::str::from_utf8;

use hex::FromHex;
use log::{error, info, debug};
use rand::random;

enum Body<'a> {
    Text { content_type: &'a str, content: &'a str },
    Blob { content_type: &'a str, content: &'a [u8] },
    None,
}

pub struct RTSPClient {
    c_handle: *mut rtspcl_s,

    headers: Vec<(String, String)>,
}

impl RTSPClient {
    pub fn new(user_agent: &str) -> Option<RTSPClient> {
        let c_handle = unsafe { rtspcl_create(CString::new(user_agent).unwrap().into_raw()) };
        if c_handle.is_null() { None } else { Some(RTSPClient { c_handle, headers: vec!() }) }
    }

    // bool rtspcl_set_useragent(struct rtspcl_s *p, const char *name);

    pub fn connect(&self, local: Ipv4Addr, host: Ipv4Addr, destport: u16, sid: &str) -> Result<(), Box<std::error::Error>> {
        let mut name: sockaddr_in = sockaddr_in {
            sin_len: 0,
            sin_family: 0,
            sin_port: 0,
            sin_addr: in_addr { s_addr: 0 },
            sin_zero: [0; 8usize],
        };

        let mut myport: u16 = 0;
        let mut namelen: u32 = size_of::<sockaddr_in>() as u32;

        unsafe {
            (*self.c_handle).session = ptr::null_mut();
            (*self.c_handle).fd = open_tcp_socket(local.into(), &mut myport);
            if (*self.c_handle).fd == -1 { panic!("open_tcp_socket failed"); }
            if !get_tcp_connect_by_host((*self.c_handle).fd, host.into(), destport) { panic!("get_tcp_connect_by_host failed"); }

            getsockname((*self.c_handle).fd, ((&mut name) as *mut sockaddr_in) as *mut sockaddr, &mut namelen);
            memcpy(((&mut (*self.c_handle).local_addr) as *mut in_addr) as *mut c_void, ((&mut name.sin_addr) as *mut in_addr) as *mut c_void, size_of::<in_addr>() as u64);
        }

        let url = format!("rtsp://{}/{}", host, sid);
        unsafe { strcpy(&mut (*self.c_handle).url[0], CString::new(url).unwrap().into_raw()); }

        Ok(())
    }

    pub fn disconnect(&self) -> Result<(), Box<std::error::Error>> {
        let success = unsafe { rtspcl_disconnect(self.c_handle) };
        if success { Ok(()) } else { panic!("Failed to disconnect") }
    }

    // bool rtspcl_is_connected(struct rtspcl_s *p);
    // bool rtspcl_is_sane(struct rtspcl_s *p);
    // bool rtspcl_options(struct rtspcl_s *p, key_data_t *rkd);

    pub fn pair_verify(&self, secret_hex: &str) -> Result<(), Box<std::error::Error>> {
        // retrieve authentication keys from secret
        let secret = <[u8; ed25519_secret_key_size]>::from_hex(secret_hex)?;
        let mut auth_pub = [0u8; ed25519_public_key_size];
        let mut auth_priv = [0u8; ed25519_private_key_size];
        unsafe { ed25519_CreateKeyPair(&mut auth_pub[0], &mut auth_priv[0], ptr::null_mut(), &secret[0]); }
        drop(secret);

        // create a verification public key
        let mut verify_pub = [0u8; ed25519_public_key_size];
        let mut verify_secret: [u8; ed25519_secret_key_size] = random();
        unsafe { curve25519_dh_CalculatePublicKey(&mut verify_pub[0], &mut verify_secret[0]); }

        // POST the auth_pub and verify_pub concataned
        let mut buf = Vec::with_capacity(4 + ed25519_public_key_size * 2);
        buf.write(b"\x01\x00\x00\x00")?;
        buf.write(&verify_pub)?;
        buf.write(&auth_pub)?;

        let (_, content) = self.exec_request("POST", Body::Blob { content_type: "application/octet-stream", content: &buf }, vec!(), Some("/pair-verify"))
            .map_err(|err| { error!("AppleTV verify step 1 failed (pair again)"); err })?;

        drop(buf);

        // FIXME: flag to self.exec_request should make it return binary response
        let content = content.as_bytes();

        // get atv_pub and atv_data then create shared secret
        let atv_pub = &content[0..ed25519_public_key_size];
        let atv_data = &content[(content.len() - ed25519_public_key_size)..];
        let mut shared_secret = [0u8; ed25519_secret_key_size];
        unsafe { curve25519_dh_CreateSharedKey(&mut shared_secret[0], &atv_pub[0], &mut verify_secret[0]); }

        // build AES-key & AES-iv from shared secret digest
        let mut aes_key: [u8; 16] = unsafe { std::mem::uninitialized() };
        unsafe {
            let header = b"Pair-Verify-AES-Key";
            let mut digest: SHA512_CTX = std::mem::uninitialized();

            SHA512_Init(&mut digest);
            SHA512_Update(&mut digest, (&header[0] as *const u8) as *const c_void, header.len());
            SHA512_Update(&mut digest, (&shared_secret[0] as *const u8) as *const c_void, shared_secret.len());
            SHA512_Final(&mut aes_key[0], &mut digest);
        }

        let mut aes_iv: [u8; 16] = unsafe { std::mem::uninitialized() };
        unsafe {
            let header = b"Pair-Verify-AES-IV";
            let mut digest: SHA512_CTX = std::mem::uninitialized();

            SHA512_Init(&mut digest);
            SHA512_Update(&mut digest, (&header[0] as *const u8) as *const c_void, header.len());
            SHA512_Update(&mut digest, (&shared_secret[0] as *const u8) as *const c_void, shared_secret.len());
            SHA512_Final(&mut aes_iv[0], &mut digest);
        }

        // sign the verify_pub and atv_pub
        let mut signed_keys: [u8; ed25519_signature_size] = unsafe { std::mem::uninitialized() };
        unsafe {
            let mut message = Vec::with_capacity(ed25519_public_key_size * 2);
            message.write(&verify_pub)?;
            message.write(&atv_pub)?;
            ed25519_SignMessage(&mut signed_keys[0], &auth_priv[0], ptr::null(), &message[0], message.len());
        }

        // encrypt the signed result + atv_data, add 4 NULL bytes at the beginning
        let mut ctx: aes_ctr_context = unsafe { std::mem::uninitialized() };
        let mut buf = [0u8; 4 + ed25519_public_key_size * 2];
        let four_null_bytes = [0u8; 4];

        // FIXME: https://github.com/philippe44/RAOP-Player/issues/12
        unsafe {
            aes_ctr_init(&mut ctx, &mut aes_key[0], &mut aes_iv[0], CTR_BIG_ENDIAN);
            memcpy((&mut buf[0] as *mut u8) as *mut c_void, (&atv_data[0] as *const u8) as *const c_void, atv_data.len() as u64);
            aes_ctr_encrypt(&mut ctx, &mut buf[0], buf.len());
            memcpy((&mut buf[4] as *mut u8) as *mut c_void, (&signed_keys[0] as *const u8) as *const c_void, signed_keys.len() as u64);
            aes_ctr_encrypt(&mut ctx, &mut buf[4], ed25519_signature_size);
            memcpy((&mut buf[0] as *mut u8) as *mut c_void, (&four_null_bytes[0] as *const u8) as *const c_void, four_null_bytes.len() as u64);
        }
        let len = ed25519_signature_size + 4;

        self.exec_request("POST", Body::Blob { content_type: "application/octet-stream", content: &buf[0..len] }, vec!(), Some("/pair-verify"))
            .map_err(|err| { error!("AppleTV verify step 2 failed (pair again)"); err })
            .map(|_| ())
    }

    pub fn auth_setup(&self) -> Result<(), Box<std::error::Error>> {
        let success = unsafe { rtspcl_auth_setup(self.c_handle) };
        if success { Ok(()) } else { panic!("Failed to setup auth") }
    }

    pub fn announce_sdp(&self, sdp: &str) -> Result<(), Box<std::error::Error>> {
        self.exec_request("ANNOUNCE", Body::Text { content_type: "application/sdp", content: sdp }, vec!(), None).map(|_| ())
    }

    pub fn setup(&self, control_port: u16, timing_port: u16) -> Result<Vec<(String, String)>, Box<std::error::Error>> {
        let transport = format!("RTP/AVP/UDP;unicast;interleaved=0-1;mode=record;control_port={};timing_port={}", control_port, timing_port);
        let (headers, _) = self.exec_request("SETUP", Body::None, vec!(("Transport", &transport)), None)?;
        let session = headers.iter().find(|header| header.0.to_lowercase() == "session").map(|header| header.1.as_str());

        if let Some(session) = session {
            unsafe { (*self.c_handle).session = CString::new(session).unwrap().into_raw(); }
            debug!("<------- : session:{}", session);
        } else {
            error!("no session in response");
            panic!("no session in response");
        }

        Ok(headers)
    }

    pub fn record(&self, start_seq: u16, start_ts: u64) -> Result<Vec<(String, String)>, Box<std::error::Error>> {
        if unsafe { (*self.c_handle).session.is_null() } {
            error!("no session in progress");
            panic!("no session in progress");
        }

        let info = format!("seq={};rtptime={}", start_seq, start_ts);
        let headers = vec!(("Range", "npt=0-"), ("RTP-Info", &info));

        self.exec_request("RECORD", Body::None, headers, None).map(|result| result.0)
    }

    pub fn set_parameter(&self, param: &str) -> Result<(), Box<std::error::Error>> {
        self.exec_request("SET_PARAMETER", Body::Text { content_type: "text/parameters", content: param }, vec!(), None).map(|_| ())
    }

    pub fn flush(&self, seq_number: u16, timestamp: u64) -> Result<(), Box<std::error::Error>> {
        let info = format!("seq={};rtptime={}", seq_number, timestamp);
        self.exec_request("FLUSH", Body::None, vec!(("RTP-Info", &info)), None).map(|_| ())
    }

    // bool rtspcl_set_daap(struct rtspcl_s *p, u32_t timestamp, int count, va_list args);
    // bool rtspcl_set_artwork(struct rtspcl_s *p, u32_t timestamp, char *content_type, int size, char *image);

    pub fn add_exthds(&mut self, key: &str, data: &str) -> Result<(), Box<std::error::Error>> {
        self.headers.push((key.to_owned(), data.to_owned()));

        let success = unsafe { rtspcl_add_exthds(self.c_handle, CString::new(key).unwrap().into_raw(), CString::new(data).unwrap().into_raw()) };
        if success { Ok(()) } else { panic!("Failed to add exthds") }
    }

    pub fn mark_del_exthds(&mut self, key: &str) -> Result<(), Box<std::error::Error>> {
        self.headers.retain(|header| header.0 != key);

        let success = unsafe { rtspcl_mark_del_exthds(self.c_handle, CString::new(key).unwrap().into_raw()) };
        if success { Ok(()) } else { panic!("Failed to del exthds") }
    }

    pub fn local_ip(&self) -> Result<String, Box<std::error::Error>> {
        Ok(unsafe { CStr::from_ptr(rtspcl_local_ip(self.c_handle)).to_str()?.to_owned() })
    }

    // static bool exec_request(struct rtspcl_s *rtspcld, char *cmd, char *content_type,
    //                 char *content, int length, int get_response, key_data_t *hds,
    //                 key_data_t *rkd, char **resp_content, int *resp_len, char* url)
    fn exec_request(&self, cmd: &str, body: Body, headers: Vec<(&str, &str)>, url: Option<&str>) -> Result<(Vec<(String, String)>, String), Box<std::error::Error>> {
        // char line[2048];
        // char *req;
        // char buf[128];
        // const char delimiters[] = " ";
        // char *token,*dp;
        // int i,j, rval, len, clen;
        // int timeout = 10000; // msec unit
        // struct pollfd pfds;
        // key_data_t lkd[MAX_KD], *pkd;

        unsafe {
            if (*self.c_handle).fd == -1 {
                panic!("exec_request called without file descriptor");
            }

            // FIXME: Wait for "Normal data may be written without blocking."
            // pfds.fd = rtspcld->fd;
            // pfds.events = POLLOUT;
            // i = poll(&pfds, 1, 0);
            // if (i == -1 || (pfds.revents & POLLERR) || (pfds.revents & POLLHUP)) return false;

            let mut req = Vec::new();

            let url = url.unwrap_or_else(|| {
                CStr::from_ptr(&(*self.c_handle).url[0]).to_str().unwrap()
            });

            write!(&mut req, "{} {} RTSP/1.0\r\n", cmd, url)?;

            for (key, value) in &headers {
                write!(&mut req, "{}: {}\r\n", key, value)?;
            }

            if let Body::Text { ref content_type, ref content } = body {
                write!(&mut req, "Content-Type: {}\r\n", content_type)?;
                write!(&mut req, "Content-Length: {}\r\n", content.len())?;
            }

            if let Body::Blob { ref content_type, ref content } = body {
                write!(&mut req, "Content-Type: {}\r\n", content_type)?;
                write!(&mut req, "Content-Length: {}\r\n", content.len())?;
            }

            (*self.c_handle).cseq += 1;
            write!(&mut req, "CSeq: {}\r\n", (*self.c_handle).cseq)?;

            let useragent = CStr::from_ptr((*self.c_handle).useragent).to_str().unwrap();
            write!(&mut req, "User-Agent: {}\r\n", useragent)?;

            for (key, value) in &self.headers {
                write!(&mut req, "{}: {}\r\n", key, value)?;
            }

            if !(*self.c_handle).session.is_null() {
                let session = CStr::from_ptr((*self.c_handle).session).to_str().unwrap();
                write!(&mut req, "Session: {}\r\n", session)?;
            }

            write!(&mut req, "\r\n")?;

            if let Body::Text { content_type: _, ref content } = body {
                write!(&mut req, "{}", content)?;
            }

            if let Body::Blob { content_type: _, ref content } = body {
                req.write(content)?;
            }

            let len = req.len();
            let rval = send((*self.c_handle).fd, CString::new(req.clone()).unwrap().into_raw() as *const c_void, len, 0);

            match body {
                Body::Text { content_type: _, content: _ } => debug!("----> : write {}", from_utf8(&req).unwrap()),
                Body::Blob { content_type: _, content: _ } => debug!("----> : send binary request"),
                Body::None => debug!("----> : write {}", from_utf8(&req).unwrap()),
            }

            if rval != len as isize {
                error!("couldn't write request ({}!={})", rval, len);
            }

            let mut timeout = 10000;
            let mut line_buffer = [0i8; 2048];

            {
                let n = read_line((*self.c_handle).fd, (&mut line_buffer[0]) as *mut i8, line_buffer.len() as i32, timeout, 0);
                if n <= 0 { panic!("request failed"); }
                let line = CStr::from_ptr(&line_buffer[0]).to_str().unwrap();

                let status = line.splitn(3, ' ').skip(1).next().unwrap();

                if status != "200" {
                    error!("<------ : request failed, error {}", line);
                    panic!("request failed");
                } else {
                    debug!("<------ : {}: request ok", status);
                }
            }

            let mut response_headers: Vec<(String, String)> = vec!();
            let mut response_content_length: usize = 0;

            loop {
                let n = read_line((*self.c_handle).fd, (&mut line_buffer[0]) as *mut i8, line_buffer.len() as i32, timeout, 0);
                if n < 0 { panic!("request failed"); }
                if n == 0 { break; }
                let line = CStr::from_ptr(&line_buffer[0]).to_str().unwrap();

                debug!("<------ : {}", line);
                timeout = 1000; // once it started, it shouldn't take a long time

                let mut parts = line.splitn(2, ':').map(|part| part.trim());
                let key = parts.next().unwrap().to_owned();
                let value = parts.next().unwrap().to_owned();

                if key.to_lowercase() == "content-length" {
                    response_content_length = value.parse().unwrap();
                }

                response_headers.push((key, value));
            }

            if response_content_length == 0 {
                return Ok((response_headers, String::new()));
            }

            let data = malloc(response_content_length) as *mut u8;
            let mut size: usize = 0;

            while size < response_content_length {
                let bytes = recv((*self.c_handle).fd, data.offset(size as isize) as *mut c_void, response_content_length - size, 0);
                if bytes <= 0 { break; }
                size += bytes as usize;
            }

            if size != response_content_length {
                error!("content length receive error {}!={}", size, response_content_length);
                panic!("content length receive error");
            }

            let response_content = CStr::from_ptr(data as *const i8).to_str()?.to_owned();
            free(data as *mut c_void);

            info!("Body data {}, {}", response_content_length, response_content);

            Ok((response_headers, response_content))
        }
    }
}

impl Drop for RTSPClient {
    fn drop(&mut self) {
        unsafe { rtspcl_remove_all_exthds(self.c_handle); }
        unsafe { rtspcl_destroy(self.c_handle); }
    }
}
