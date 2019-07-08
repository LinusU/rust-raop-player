use std::fmt::Write;
use std::str::from_utf8;

use bytes::BytesMut;
use log::{error, info, debug};
use tokio::codec::{Decoder, Encoder};

enum DecodingState {
    Empty,
    ReadingStatus { status: Vec<u8> },
    ReadingHeaderKey { status: u32, key: Vec<u8>, headers: Vec<(String, String)> },
    ReadingHeaderValue { status: u32, key: String, value: Vec<u8>, headers: Vec<(String, String)> },
    ReadingBody { status: u32, headers: Vec<(String, String)>, body: Vec<u8>, bytes_left: usize },
}

pub struct RtspCodec {
    decoding_index: usize,
    decoding_state: Option<DecodingState>,
    encoding_cseq: u64,
    encoding_user_agent: String,
}

pub struct RtspResponse {
    pub status: u32,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

pub enum Body {
    Text { content_type: String, content: String },
    Blob { content_type: String, content: Vec<u8> },
    None,
}

pub struct RtspRequest {
    pub cmd: String,
    pub url: String,
    pub session: Option<String>,
    pub headers: Vec<(String, String)>,
    pub body: Body,
}

impl RtspCodec {
    pub fn new(user_agent: &str) -> RtspCodec {
        RtspCodec {
            decoding_index: 0,
            decoding_state: Some(DecodingState::Empty),
            encoding_cseq: 0,
            encoding_user_agent: user_agent.to_owned(),
        }
    }
}

impl DecodingState {
    fn feed_byte(self, byte: u8) -> (Option<RtspResponse>, Self) {
        match self {
            DecodingState::Empty => {
                (None, DecodingState::ReadingStatus { status: vec![byte] })
            }
            DecodingState::ReadingStatus { mut status } => {
                if byte == b'\n' {
                    let status_line = String::from_utf8(status).expect("invalid utf8 data");
                    let status: u32 = status_line.trim().splitn(3, ' ').skip(1).next().unwrap().parse().unwrap();

                    if status == 200 {
                        debug!("<------ : {}: request ok", status);
                    } else {
                        error!("<------ : request failed, status {}", status);
                    }

                    (None, DecodingState::ReadingHeaderKey { status, key: vec![], headers: vec![] })
                } else {
                    status.push(byte);
                    (None, DecodingState::ReadingStatus { status })
                }
            }
            DecodingState::ReadingHeaderKey { status, mut key, headers } => {
                match byte {
                    b'\n' => {
                        let bytes_left: usize = headers.iter()
                            .find(|(key, _)| key.to_lowercase() == "content-length")
                            .map(|(_, value)| value.parse().unwrap())
                            .unwrap_or(0);

                        if bytes_left == 0 {
                            (Some(RtspResponse { status, headers, body: vec![] }), DecodingState::Empty)
                        } else {
                            (None, DecodingState::ReadingBody { status, headers, body: vec![], bytes_left })
                        }
                    }
                    b':' => {
                        let key = String::from_utf8(key).expect("invalid utf8 data").trim().to_owned();
                        (None, DecodingState::ReadingHeaderValue { status, key, value: vec![], headers })
                    }
                    _ => {
                        key.push(byte);
                        (None, DecodingState::ReadingHeaderKey { status, key, headers })
                    }
                }
            }
            DecodingState::ReadingHeaderValue { status, key, mut value, mut headers } => {
                match byte {
                    b'\n' => {
                        let value = String::from_utf8(value).expect("invalid utf8 data").trim().to_owned();
                        debug!("<------ : {}: {}", key, value);
                        headers.push((key, value));
                        (None, DecodingState::ReadingHeaderKey { status, key: vec![], headers })
                    }
                    _ => {
                        value.push(byte);
                        (None, DecodingState::ReadingHeaderValue { status, key, value, headers })
                    }
                }
            }
            DecodingState::ReadingBody { status, headers, mut body, mut bytes_left } => {
                body.push(byte);
                bytes_left -= 1;

                if bytes_left == 0 {
                    info!("Body data {}, {}", body.len(), String::from_utf8(body.clone()).expect("invalid utf8 data"));
                    (Some(RtspResponse { status, headers, body }), DecodingState::Empty)
                } else {
                    (None, DecodingState::ReadingBody { status, headers, body, bytes_left })
                }
            }
        }
    }
}

impl Decoder for RtspCodec {
    type Item = RtspResponse;
    type Error = std::io::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        loop {
            if self.decoding_index >= src.len() {
                return Ok(None)
            }

            let byte = src[self.decoding_index];
            self.decoding_index += 1;

            let (response, state) = self.decoding_state.take().unwrap().feed_byte(byte);
            self.decoding_state = Some(state);

            if let Some(response) = response {
                let _ = src.split_to(self.decoding_index);
                self.decoding_index = 0;
                return Ok(Some(response));
            }
        }
    }
}

impl Encoder for RtspCodec {
    type Item = RtspRequest;
    type Error = std::io::Error;

    fn encode(&mut self, item: Self::Item, dst: &mut BytesMut) -> Result<(), Self::Error> {
        write!(dst, "{} {} RTSP/1.0\r\n", item.cmd, item.url).unwrap();

        for (key, value) in &item.headers {
            write!(dst, "{}: {}\r\n", key, value).unwrap();
        }

        if let Body::Text { ref content_type, ref content } = item.body {
            write!(dst, "Content-Type: {}\r\n", content_type).unwrap();
            write!(dst, "Content-Length: {}\r\n", content.len()).unwrap();
        }

        if let Body::Blob { ref content_type, ref content } = item.body {
            write!(dst, "Content-Type: {}\r\n", content_type).unwrap();
            write!(dst, "Content-Length: {}\r\n", content.len()).unwrap();
        }

        self.encoding_cseq += 1;
        write!(dst, "CSeq: {}\r\n", self.encoding_cseq).unwrap();
        write!(dst, "User-Agent: {}\r\n", self.encoding_user_agent).unwrap();

        if let Some(ref session) = item.session {
            write!(dst, "Session: {}\r\n", session).unwrap();
        }

        write!(dst, "\r\n").unwrap();

        if let Body::Text { content_type: _, ref content } = item.body {
            write!(dst, "{}", content).unwrap();
        }

        if let Body::Blob { content_type: _, ref content } = item.body {
            dst.extend_from_slice(content);
        }

        match item.body {
            Body::Text { content_type: _, content: _ } => debug!("----> : write {}", from_utf8(&dst).unwrap()),
            Body::Blob { content_type: _, content: _ } => debug!("----> : send binary request"),
            Body::None => debug!("----> : write {}", from_utf8(&dst).unwrap()),
        }

        Ok(())
    }
}
