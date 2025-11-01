use std::io::Write;
use std::net::IpAddr;

use aes::{Aes128, cipher::{KeyIvInit, StreamCipher}};
use ctr::Ctr128BE;
use ed25519_dalek::{SecretKey, SigningKey, PUBLIC_KEY_LENGTH, Signer, Signature};
use hex::FromHex;
use log::{error, debug};
use sha2::{Sha512, Digest};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpStream, ToSocketAddrs};
use x25519_dalek::{StaticSecret, PublicKey};

use crate::frames::Frames;
use crate::meta_data::MetaDataItem;
use crate::serialization::Serializable;

mod error;
mod response;

pub use self::error::RtspError;
use self::response::{Response, ResponseBuilder};

enum Body<'a> {
    Text { content_type: &'a str, content: &'a str },
    Blob { content_type: &'a str, content: &'a [u8] },
    None,
}

struct RequestBuilder(Vec<u8>);

#[allow(clippy::write_with_newline)]
impl RequestBuilder {
    fn new(cmd: &str, url: &str) -> RequestBuilder {
        let mut req = Vec::new();
        write!(&mut req, "{} {} RTSP/1.0\r\n", cmd, url).unwrap();
        debug!("----> {} {} RTSP/1.0", cmd, url);
        RequestBuilder(req)
    }

    fn header(&mut self, name: &str, value: &str) {
        write!(&mut self.0, "{}: {}\r\n", name, value).unwrap();
        debug!("----> {}: {}", name, value);
    }

    fn body(mut self, value: Body) -> Vec<u8> {
        write!(&mut self.0, "\r\n").unwrap();
        debug!("----> ");

        match value {
            Body::Text { ref content, .. } => {
                write!(&mut self.0, "{}", content).unwrap();
                for line in content.lines() {
                    debug!("----> {}", line);
                }
            }

            Body::Blob { ref content, .. } => {
                self.0.extend_from_slice(content);
                debug!("----> ({} bytes binary data)", content.len());
            }

            Body::None => {},
        }

        self.0
    }
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
    pub async fn connect<A: ToSocketAddrs>(addr: A, sid: &str, user_agent: &str, headers: &[(&str, &str)]) -> Result<RTSPClient, Box<dyn std::error::Error>> {
        let socket = TcpStream::connect(addr).await?;
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

    pub async fn options(&mut self, headers: Vec<(&str, &str)>) -> Result<(), RtspError> {
        self.exec_request("OPTIONS", Body::None, headers, Some("*")).await.map(|_| ())
    }

    pub async fn pair_verify(&mut self, secret_hex: &str) -> Result<(), RtspError> {
        // retrieve authentication keys from secret
        let secret = SecretKey::from_hex(secret_hex)?;
        let auth_priv = SigningKey::from_bytes(&secret);

        // create a verification public key
        let verify_secret = StaticSecret::random_from_rng(rand::thread_rng());
        let verify_pub = PublicKey::from(&verify_secret);

        // POST the auth_pub and verify_pub concataned
        let mut buf = Vec::with_capacity(4 + PUBLIC_KEY_LENGTH * 2);
        buf.extend(b"\x01\x00\x00\x00");
        buf.extend_from_slice(verify_pub.as_bytes());
        buf.extend_from_slice(auth_priv.verifying_key().as_bytes());

        let (_, content) = self.exec_request("POST", Body::Blob { content_type: "application/octet-stream", content: &buf }, vec!(), Some("/pair-verify")).await
            .map_err(|err| { error!("AppleTV verify step 1 failed (pair again)"); err })?;

        drop(buf);

        // get atv_pub and atv_data then create shared secret
        assert_eq!(content.len(), PUBLIC_KEY_LENGTH * 2);
        let atv_pub: [u8; PUBLIC_KEY_LENGTH] = content[0..PUBLIC_KEY_LENGTH].try_into().unwrap();
        let atv_data: [u8; PUBLIC_KEY_LENGTH] = content[PUBLIC_KEY_LENGTH..].try_into().unwrap();

        let shared_secret = {
            let secret_key = StaticSecret::from(atv_data);
            let peer_key = PublicKey::from(atv_pub);

            secret_key.diffie_hellman(&peer_key)
        };

        // build AES-key & AES-iv from shared secret digest
        let aes_key: [u8; 16] = {
            let mut hasher = Sha512::new();
            hasher.update(b"Pair-Verify-AES-Key");
            hasher.update(&shared_secret);
            hasher.finalize()[0..16].try_into().unwrap()
        };

        let aes_iv: [u8; 16] = {
            let mut hasher = Sha512::new();
            hasher.update(b"Pair-Verify-AES-IV");
            hasher.update(&shared_secret);
            hasher.finalize()[0..16].try_into().unwrap()
        };

        // sign the verify_pub and atv_pub
        let signed_keys: [u8; Signature::BYTE_SIZE] = {
            let mut message = Vec::with_capacity(PUBLIC_KEY_LENGTH * 2);
            message.extend_from_slice(verify_pub.as_bytes());
            message.extend_from_slice(&atv_pub);
            auth_priv.sign(&message).into()
        };

        // encrypt the signed result + atv_data, add 4 NULL bytes at the beginning
        let mut ctx = Ctr128BE::<Aes128>::new(&aes_key.into(), &aes_iv.into());
        let mut buf = [0u8; 4 + Signature::BYTE_SIZE];

        // Encrypt <atv_data>, discard result
        let mut unused = [0u8; PUBLIC_KEY_LENGTH];
        ctx.apply_keystream_b2b(&atv_data, &mut unused).expect("encryption failed");

        // Encrypt <signed> and keep result as the signature <signature> (64 bytes)
        ctx.apply_keystream_b2b(&signed_keys, &mut buf[4..]).expect("encryption failed");

        // Concatenate this <signature> with a 4 bytes header “\0x00\0x00\0x00\0x00”
        buf[0] = 0;
        buf[1] = 0;
        buf[2] = 0;
        buf[3] = 0;

        // ...and send this in the body of an HTTP POST request
        self.exec_request("POST", Body::Blob { content_type: "application/octet-stream", content: &buf }, vec!(), Some("/pair-verify")).await
            .map_err(|err| { error!("AppleTV verify step 2 failed (pair again)"); err })
            .map(|_| ())
    }

    pub async fn auth_setup(&mut self) -> Result<(), RtspError> {
        let secret = StaticSecret::random_from_rng(rand::thread_rng());
        let pub_key = PublicKey::from(&secret);

        let mut buf = Vec::with_capacity(1 + PUBLIC_KEY_LENGTH);
        buf.push(0x01);
        buf.extend_from_slice(pub_key.as_bytes());

        self.exec_request("POST", Body::Blob { content_type: "application/octet-stream", content: &buf }, vec!(), Some("/auth-setup")).await
            .map_err(|err| { error!("auth-setup failed"); err })
            .map(|_| ())
    }

    pub async fn announce_sdp(&mut self, sdp: &str) -> Result<(), RtspError> {
        self.exec_request("ANNOUNCE", Body::Text { content_type: "application/sdp", content: sdp }, vec!(), None).await.map(|_| ())
    }

    pub async fn setup(&mut self, control_port: u16, timing_port: u16) -> Result<Vec<(String, String)>, Box<dyn std::error::Error>> {
        let transport = format!("RTP/AVP/UDP;unicast;interleaved=0-1;mode=record;control_port={};timing_port={}", control_port, timing_port);
        let (headers, _) = self.exec_request("SETUP", Body::None, vec!(("Transport", &transport)), None).await?;
        let session = headers.iter().find(|header| header.0.to_lowercase() == "session").map(|header| header.1.as_str());

        if let Some(session) = session {
            self.session = Some(session.to_owned());
            debug!("got session from remote: {}", session);
        } else {
            error!("no session in response");
            panic!("no session in response");
        }

        Ok(headers)
    }

    pub async fn record(&mut self, start_seq: u16, start_ts: Frames) -> Result<Vec<(String, String)>, RtspError> {
        if self.session.is_none() {
            error!("no session in progress");
            panic!("no session in progress");
        }

        let info = format!("seq={};rtptime={}", start_seq, start_ts);
        let headers = vec!(("Range", "npt=0-"), ("RTP-Info", &info));

        self.exec_request("RECORD", Body::None, headers, None).await.map(|result| result.0)
    }

    pub async fn set_parameter(&mut self, param: &str) -> Result<(), RtspError> {
        self.exec_request("SET_PARAMETER", Body::Text { content_type: "text/parameters", content: param }, vec!(), None).await.map(|_| ())
    }

    pub async fn set_meta_data(&mut self, timestamp: Frames, meta_data: MetaDataItem) -> Result<(), RtspError> {
        let rtptime = format!("rtptime={}", timestamp);
        let body = Body::Blob { content_type: "application/x-dmap-tagged", content: &meta_data.as_bytes() };

        self.exec_request("SET_PARAMETER", body, vec![("RTP-Info", &rtptime)], None).await.map(|_| ())
    }

    pub async fn flush(&mut self, seq_number: u16, timestamp: Frames) -> Result<(), RtspError> {
        let info = format!("seq={};rtptime={}", seq_number, timestamp);
        self.exec_request("FLUSH", Body::None, vec!(("RTP-Info", &info)), None).await.map(|_| ())
    }

    pub async fn teardown(&mut self) -> Result<(), RtspError> {
        self.exec_request("TEARDOWN", Body::None, vec!(), None).await.map(|_| ())
    }

    // bool rtspcl_set_daap(struct rtspcl_s *p, u32_t timestamp, int count, va_list args);
    // bool rtspcl_set_artwork(struct rtspcl_s *p, u32_t timestamp, char *content_type, int size, char *image);

    pub fn add_exthds(&mut self, key: &str, data: &str) {
        self.headers.push((key.to_owned(), data.to_owned()));
    }

    pub fn mark_del_exthds(&mut self, key: &str) {
        self.headers.retain(|header| header.0 != key);
    }

    pub fn local_ip(&self) -> Result<IpAddr, Box<dyn std::error::Error>> {
        Ok(self.socket.get_ref().local_addr()?.ip())
    }

    async fn exec_request(&mut self, cmd: &str, body: Body<'_>, headers: Vec<(&str, &str)>, url: Option<&str>) -> Result<Response, RtspError> {
        let url = url.unwrap_or_else(|| self.url.as_str());
        let mut req = RequestBuilder::new(cmd, url);

        for (key, value) in &headers {
            req.header(key, value);
        }

        if let Body::Text { ref content_type, ref content } = body {
            req.header("Content-Type", content_type);
            req.header("Content-Length", &content.len().to_string());
        }

        if let Body::Blob { ref content_type, ref content } = body {
            req.header("Content-Type", content_type);
            req.header("Content-Length", &content.len().to_string());
        }

        self.cseq += 1;
        req.header("CSeq", &self.cseq.to_string());
        req.header("User-Agent", &self.user_agent);

        for (key, value) in &self.headers {
            req.header(key, value);
        }

        if let Some(ref session) = self.session {
            req.header("Session", session);
        }

        let req = req.body(body);

        self.socket.get_mut().write_all(&req).await?;

        let mut response = {
            let mut line = String::new();
            self.socket.read_line(&mut line).await?;
            ResponseBuilder::new(&line)?
        };

        loop {
            let mut line = String::new();
            self.socket.read_line(&mut line).await?;

            if line.trim() == "" { break; }
            response.header(&line)?;
        }

        let mut data = vec![0u8; response.content_length()];
        if !data.is_empty() { self.socket.read_exact(&mut data).await?; }
        Ok(response.body(data)?)
    }
}
