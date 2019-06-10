use crate::bindings::{ed25519_public_key_size, ed25519_secret_key_size, ed25519_private_key_size, ed25519_signature_size, ed25519_CreateKeyPair, curve25519_dh_CalculatePublicKey, curve25519_dh_CreateSharedKey, ed25519_SignMessage};

use openssl_sys::{SHA512_CTX, SHA512_Init, SHA512_Update, SHA512_Final};

use std::ffi::c_void;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::ptr;
use std::str::from_utf8;

use hex::FromHex;
use log::{error, info, debug};
use openssl::symm::{Cipher, Mode, Crypter};
use rand::random;

enum Body<'a> {
    Text { content_type: &'a str, content: &'a str },
    Blob { content_type: &'a str, content: &'a [u8] },
    None,
}

pub struct RTSPClient {
    socket: BufReader<TcpStream>,
    url: String,
    cseq: u64,
    headers: Vec<(String, String)>,
    session: Option<String>,
    user_agent: String,
}

impl RTSPClient {
    pub fn connect<A: ToSocketAddrs>(addr: A, sid: &str, user_agent: &str, headers: &[(&str, &str)]) -> Result<RTSPClient, Box<std::error::Error>> {
        let socket = TcpStream::connect(addr)?;
        let peer_addr = socket.peer_addr()?;

        Ok(RTSPClient {
            socket: BufReader::new(socket),
            url: format!("rtsp://{}/{}", peer_addr.ip(), sid),
            cseq: 0,
            headers: headers.iter().map(|header| (header.0.to_owned(), header.1.to_owned())).collect(),
            session: None,
            user_agent: user_agent.to_owned(),
        })
    }

    // bool rtspcl_set_useragent(struct rtspcl_s *p, const char *name);

    // bool rtspcl_is_connected(struct rtspcl_s *p);
    // bool rtspcl_is_sane(struct rtspcl_s *p);
    // bool rtspcl_options(struct rtspcl_s *p, key_data_t *rkd);

    pub fn pair_verify(&mut self, secret_hex: &str) -> Result<(), Box<std::error::Error>> {
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
        buf.extend(b"\x01\x00\x00\x00");
        buf.extend_from_slice(&verify_pub);
        buf.extend_from_slice(&auth_pub);

        let (_, content) = self.exec_request("POST", Body::Blob { content_type: "application/octet-stream", content: &buf }, vec!(), Some("/pair-verify"))
            .map_err(|err| { error!("AppleTV verify step 1 failed (pair again)"); err })?;

        drop(buf);

        // FIXME: flag to self.exec_request should make it return binary response
        let content = content.as_bytes();

        // get atv_pub and atv_data then create shared secret
        let atv_pub = &content[0..ed25519_public_key_size];
        let atv_data = &content[ed25519_public_key_size..];
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
            message.extend_from_slice(&verify_pub);
            message.extend_from_slice(&atv_pub);
            ed25519_SignMessage(&mut signed_keys[0], &auth_priv[0], ptr::null(), &message[0], message.len());
        }

        // encrypt the signed result + atv_data, add 4 NULL bytes at the beginning
        let mut ctx = Crypter::new(Cipher::aes_128_ctr(), Mode::Encrypt, &aes_key, Some(&aes_iv))?;
        let mut buf = [0u8; 4 + ed25519_signature_size];

        // Encrypt <atv_data>, discard result
        ctx.update(&atv_data, &mut buf)?;
        // Encrypt <signed> and keep result as the signature <signature> (64 bytes)
        ctx.update(&signed_keys, &mut buf[4..])?;

        // Concatenate this <signature> with a 4 bytes header “\0x00\0x00\0x00\0x00”
        buf[0] = 0;
        buf[1] = 0;
        buf[2] = 0;
        buf[3] = 0;

        // ...and send this in the body of an HTTP POST request
        self.exec_request("POST", Body::Blob { content_type: "application/octet-stream", content: &buf }, vec!(), Some("/pair-verify"))
            .map_err(|err| { error!("AppleTV verify step 2 failed (pair again)"); err })
            .map(|_| ())
    }

    pub fn auth_setup(&mut self) -> Result<(), Box<std::error::Error>> {
        let mut pub_key = [0u8; ed25519_public_key_size];
        let mut secret: [u8; ed25519_secret_key_size] = random();
        unsafe { curve25519_dh_CalculatePublicKey(&mut pub_key[0], &mut secret[0]); }

        let mut buf = Vec::with_capacity(1 + ed25519_public_key_size);
        buf.push(0x01);
        buf.extend_from_slice(&pub_key);

        self.exec_request("POST", Body::Blob { content_type: "application/octet-stream", content: &buf }, vec!(), Some("/auth-setup"))
            .map_err(|err| { error!("auth-setup failed"); err })
            .map(|_| ())
    }

    pub fn announce_sdp(&mut self, sdp: &str) -> Result<(), Box<std::error::Error>> {
        self.exec_request("ANNOUNCE", Body::Text { content_type: "application/sdp", content: sdp }, vec!(), None).map(|_| ())
    }

    pub fn setup(&mut self, control_port: u16, timing_port: u16) -> Result<Vec<(String, String)>, Box<std::error::Error>> {
        let transport = format!("RTP/AVP/UDP;unicast;interleaved=0-1;mode=record;control_port={};timing_port={}", control_port, timing_port);
        let (headers, _) = self.exec_request("SETUP", Body::None, vec!(("Transport", &transport)), None)?;
        let session = headers.iter().find(|header| header.0.to_lowercase() == "session").map(|header| header.1.as_str());

        if let Some(session) = session {
            self.session = Some(session.to_owned());
            debug!("<------- : session:{}", session);
        } else {
            error!("no session in response");
            panic!("no session in response");
        }

        Ok(headers)
    }

    pub fn record(&mut self, start_seq: u16, start_ts: u64) -> Result<Vec<(String, String)>, Box<std::error::Error>> {
        if self.session.is_none() {
            error!("no session in progress");
            panic!("no session in progress");
        }

        let info = format!("seq={};rtptime={}", start_seq, start_ts);
        let headers = vec!(("Range", "npt=0-"), ("RTP-Info", &info));

        self.exec_request("RECORD", Body::None, headers, None).map(|result| result.0)
    }

    pub fn set_parameter(&mut self, param: &str) -> Result<(), Box<std::error::Error>> {
        self.exec_request("SET_PARAMETER", Body::Text { content_type: "text/parameters", content: param }, vec!(), None).map(|_| ())
    }

    pub fn flush(&mut self, seq_number: u16, timestamp: u64) -> Result<(), Box<std::error::Error>> {
        let info = format!("seq={};rtptime={}", seq_number, timestamp);
        self.exec_request("FLUSH", Body::None, vec!(("RTP-Info", &info)), None).map(|_| ())
    }

    // bool rtspcl_set_daap(struct rtspcl_s *p, u32_t timestamp, int count, va_list args);
    // bool rtspcl_set_artwork(struct rtspcl_s *p, u32_t timestamp, char *content_type, int size, char *image);

    pub fn add_exthds(&mut self, key: &str, data: &str) {
        self.headers.push((key.to_owned(), data.to_owned()));
    }

    pub fn mark_del_exthds(&mut self, key: &str) {
        self.headers.retain(|header| header.0 != key);
    }

    pub fn local_ip(&self) -> Result<String, Box<std::error::Error>> {
        Ok(self.socket.get_ref().local_addr()?.ip().to_string())
    }

    // static bool exec_request(struct rtspcl_s *rtspcld, char *cmd, char *content_type,
    //                 char *content, int length, int get_response, key_data_t *hds,
    //                 key_data_t *rkd, char **resp_content, int *resp_len, char* url)
    fn exec_request(&mut self, cmd: &str, body: Body, headers: Vec<(&str, &str)>, url: Option<&str>) -> Result<(Vec<(String, String)>, String), Box<std::error::Error>> {
        // char line[2048];
        // char *req;
        // char buf[128];
        // const char delimiters[] = " ";
        // char *token,*dp;
        // int i,j, rval, len, clen;
        // int timeout = 10000; // msec unit
        // struct pollfd pfds;
        // key_data_t lkd[MAX_KD], *pkd;

        // FIXME: Wait for "Normal data may be written without blocking."
        // pfds.fd = rtspcld->fd;
        // pfds.events = POLLOUT;
        // i = poll(&pfds, 1, 0);
        // if (i == -1 || (pfds.revents & POLLERR) || (pfds.revents & POLLHUP)) return false;

        let mut req = Vec::new();

        let url = url.unwrap_or_else(|| self.url.as_str());

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

        self.cseq += 1;
        write!(&mut req, "CSeq: {}\r\n", self.cseq)?;
        write!(&mut req, "User-Agent: {}\r\n", self.user_agent)?;

        for (key, value) in &self.headers {
            write!(&mut req, "{}: {}\r\n", key, value)?;
        }

        if let Some(ref session) = self.session {
            write!(&mut req, "Session: {}\r\n", session)?;
        }

        write!(&mut req, "\r\n")?;

        if let Body::Text { content_type: _, ref content } = body {
            write!(&mut req, "{}", content)?;
        }

        if let Body::Blob { content_type: _, ref content } = body {
            req.extend_from_slice(content);
        }

        self.socket.get_ref().write_all(&req)?;

        match body {
            Body::Text { content_type: _, content: _ } => debug!("----> : write {}", from_utf8(&req).unwrap()),
            Body::Blob { content_type: _, content: _ } => debug!("----> : send binary request"),
            Body::None => debug!("----> : write {}", from_utf8(&req).unwrap()),
        }

        {
            let mut line = String::new();
            self.socket.read_line(&mut line)?;

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
            let mut line = String::new();
            self.socket.read_line(&mut line)?;

            if line.trim() == "" { break; }

            debug!("<------ : {}", line);

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

        let mut data = vec![0u8; response_content_length];
        self.socket.read_exact(&mut data)?;

        let response_content = String::from_utf8(data)?;

        info!("Body data {}, {}", response_content_length, response_content);

        Ok((response_headers, response_content))
    }
}

impl Drop for RTSPClient {
    fn drop(&mut self) {
        self.exec_request("TEARDOWN", Body::None, vec!(), None).unwrap();
    }
}
