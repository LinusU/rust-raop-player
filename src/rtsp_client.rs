use std::net::ToSocketAddrs;

use hex::FromHex;
use log::{error, debug};
use openssl::sha::Sha512;
use openssl::symm::{Cipher, Mode, Crypter};
use rand::random;
use tokio::codec::Framed;
use tokio::net::TcpStream;
use tokio::reactor::Handle;
use tokio::prelude::*;

use crate::curve25519;
use crate::meta_data::MetaDataItem;
use crate::serialization::Serializable;
use crate::tokio_rtsp::{Body, RtspCodec};

pub struct RTSPClient {
    socket: Option<Framed<TcpStream, RtspCodec>>,
    url: String,
    cseq: u64,
    headers: Vec<(String, String)>,
    session: Option<String>,
    user_agent: String,
}

impl RTSPClient {
    pub fn connect<A: ToSocketAddrs>(addr: A, sid: &str, user_agent: &str, headers: &[(&str, &str)]) -> Result<RTSPClient, Box<std::error::Error>> {
        // FIXME: Connect async
        let socket = std::net::TcpStream::connect(addr)?;
        let socket = TcpStream::from_std(socket, &Handle::default())?;
        let peer_addr = socket.peer_addr()?;

        let codec = RtspCodec::new(user_agent);

        Ok(RTSPClient {
            socket: Some(Framed::new(socket, codec)),
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

    pub fn options(&mut self, headers: Vec<(String, String)>) -> Result<(), Box<std::error::Error>> {
        self.exec_request("OPTIONS", Body::None, headers, Some("*")).map(|_| ())
    }

    pub fn pair_verify(&mut self, secret_hex: &str) -> Result<(), Box<std::error::Error>> {
        // retrieve authentication keys from secret
        let secret = <[u8; curve25519::SECRET_KEY_SIZE]>::from_hex(secret_hex)?;
        let (auth_priv, auth_pub) = curve25519::create_key_pair(&secret);
        drop(secret);

        // create a verification public key
        let verify_secret: [u8; curve25519::SECRET_KEY_SIZE] = random();
        let verify_pub = curve25519::calculate_public_key(&verify_secret);

        // POST the auth_pub and verify_pub concataned
        let mut buf = Vec::with_capacity(4 + curve25519::PUBLIC_KEY_SIZE * 2);
        buf.extend(b"\x01\x00\x00\x00");
        buf.extend_from_slice(&verify_pub);
        buf.extend_from_slice(&auth_pub);

        let (_, content) = self.exec_request("POST", Body::Blob { content_type: "application/octet-stream".to_owned(), content: buf }, vec!(), Some("/pair-verify"))
            .map_err(|err| { error!("AppleTV verify step 1 failed (pair again)"); err })?;

        // FIXME: flag to self.exec_request should make it return binary response
        let content = content.as_bytes();

        // get atv_pub and atv_data then create shared secret
        let atv_pub = &content[0..curve25519::PUBLIC_KEY_SIZE];
        let atv_data = &content[curve25519::PUBLIC_KEY_SIZE..];
        let shared_secret = curve25519::create_shared_key(&atv_pub, &verify_secret);

        // build AES-key & AES-iv from shared secret digest
        let aes_key = {
            let mut hasher = Sha512::new();
            hasher.update(b"Pair-Verify-AES-Key");
            hasher.update(&shared_secret);
            &hasher.finish()[0..16]
        };

        let aes_iv = {
            let mut hasher = Sha512::new();
            hasher.update(b"Pair-Verify-AES-IV");
            hasher.update(&shared_secret);
            &hasher.finish()[0..16]
        };

        // sign the verify_pub and atv_pub
        let signed_keys = {
            let mut message = Vec::with_capacity(curve25519::PUBLIC_KEY_SIZE * 2);
            message.extend_from_slice(&verify_pub);
            message.extend_from_slice(&atv_pub);
            curve25519::sign_message(&auth_priv, &message)
        };

        // encrypt the signed result + atv_data, add 4 NULL bytes at the beginning
        let mut ctx = Crypter::new(Cipher::aes_128_ctr(), Mode::Encrypt, &aes_key, Some(&aes_iv))?;
        let mut buf = vec![0u8; 4 + curve25519::SIGNATURE_SIZE];

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
        self.exec_request("POST", Body::Blob { content_type: "application/octet-stream".to_owned(), content: buf }, vec!(), Some("/pair-verify"))
            .map_err(|err| { error!("AppleTV verify step 2 failed (pair again)"); err })
            .map(|_| ())
    }

    pub fn auth_setup(&mut self) -> Result<(), Box<std::error::Error>> {
        let secret: [u8; curve25519::SECRET_KEY_SIZE] = random();
        let pub_key = curve25519::calculate_public_key(&secret);
        drop(secret);

        let mut buf = Vec::with_capacity(1 + curve25519::PUBLIC_KEY_SIZE);
        buf.push(0x01);
        buf.extend_from_slice(&pub_key);

        self.exec_request("POST", Body::Blob { content_type: "application/octet-stream".to_owned(), content: buf }, vec!(), Some("/auth-setup"))
            .map_err(|err| { error!("auth-setup failed"); err })
            .map(|_| ())
    }

    pub fn announce_sdp(&mut self, sdp: &str) -> Result<(), Box<std::error::Error>> {
        self.exec_request("ANNOUNCE", Body::Text { content_type: "application/sdp".to_owned(), content: sdp.to_owned() }, vec!(), None).map(|_| ())
    }

    pub fn setup(&mut self, control_port: u16, timing_port: u16) -> Result<Vec<(String, String)>, Box<std::error::Error>> {
        let transport = format!("RTP/AVP/UDP;unicast;interleaved=0-1;mode=record;control_port={};timing_port={}", control_port, timing_port);
        let (headers, _) = self.exec_request("SETUP", Body::None, vec!(("Transport".to_owned(), transport)), None)?;
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
        let headers = vec!(("Range".to_owned(), "npt=0-".to_owned()), ("RTP-Info".to_owned(), info));

        self.exec_request("RECORD", Body::None, headers, None).map(|result| result.0)
    }

    pub fn set_parameter(&mut self, param: &str) -> Result<(), Box<std::error::Error>> {
        self.exec_request("SET_PARAMETER", Body::Text { content_type: "text/parameters".to_owned(), content: param.to_owned() }, vec!(), None).map(|_| ())
    }

    pub fn set_meta_data(&mut self, timestamp: u64, meta_data: MetaDataItem) -> Result<(), Box<std::error::Error>> {
        let rtptime = format!("rtptime={}", timestamp);
        let body = Body::Blob { content_type: "application/x-dmap-tagged".to_owned(), content: meta_data.as_bytes() };

        self.exec_request("SET_PARAMETER", body, vec![("RTP-Info".to_owned(), rtptime)], None).map(|_| ())
    }

    pub fn flush(&mut self, seq_number: u16, timestamp: u64) -> Result<(), Box<std::error::Error>> {
        let info = format!("seq={};rtptime={}", seq_number, timestamp);
        self.exec_request("FLUSH", Body::None, vec!(("RTP-Info".to_owned(), info)), None).map(|_| ())
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
        Ok(self.socket.as_ref().unwrap().get_ref().local_addr()?.ip().to_string())
    }

    fn exec_request(&mut self, cmd: &str, body: Body, headers: Vec<(String, String)>, url: Option<&str>) -> Result<(Vec<(String, String)>, String), Box<std::error::Error>> {
        let url = url.map(|url| url.to_owned()).unwrap_or_else(|| self.url.clone());

        let socket = self.socket.take().expect("Failed to aquire socket");
        let headers = self.headers.iter().chain(headers.iter()).map(|header| (header.0.to_owned(), header.1.to_owned())).collect();
        let future = socket.send(crate::tokio_rtsp::RtspRequest { cmd: cmd.to_owned(), url, session: self.session.clone(), headers, body }).map_err(|err| err.into());

        return future
            .and_then(|socket| {
                // FIXME: Return the socket in case of an error
                socket.into_future().map_err(|(err, _)| err.into())
            })
            .map(|(response, socket)| {
                self.socket = Some(socket);

                let response = match response {
                    None => panic!("Connection closed prematurely"),
                    Some(response) => response,
                };

                if response.status != 200 {
                    panic!("request failed");
                }

                let body = String::from_utf8(response.body).unwrap();
                return (response.headers, body);
            })
            .wait();
    }
}

impl Drop for RTSPClient {
    fn drop(&mut self) {
        self.exec_request("TEARDOWN", Body::None, vec!(), None).unwrap();
    }
}
