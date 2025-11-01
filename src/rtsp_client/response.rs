use std::error::Error;
use std::fmt::{self, Formatter, Display};
use std::num::ParseIntError;
use std::string::FromUtf8Error;

use log::debug;

use super::RtspError;

pub type Response = (Vec<(String, String)>, Vec<u8>);

#[derive(Debug)]
#[allow(clippy::enum_variant_names)]
pub enum ParseResponseError {
    InvalidStatusLine,
    InvalidStatusCode(ParseIntError),
    InvalidHeaderLine,
    InvalidBody(FromUtf8Error),
}

impl Display for ParseResponseError {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl Error for ParseResponseError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            ParseResponseError::InvalidStatusCode(source) => Some(source),
            ParseResponseError::InvalidBody(source) => Some(source),
            _ => None,
        }
    }
}

pub struct ResponseBuilder {
    status: u16,
    headers: Vec<(String, String)>,
    content_length: usize,
}

impl ResponseBuilder {
    pub fn new(status_line: &str) -> Result<ResponseBuilder, ParseResponseError> {
        debug!("<---- {}", status_line.trim());
        let status = status_line.split_whitespace().nth(1).ok_or(ParseResponseError::InvalidStatusLine)?;
        let status = status.parse().map_err(ParseResponseError::InvalidStatusCode)?;

        Ok(ResponseBuilder { status, headers: Vec::new(), content_length: 0 })
    }

    pub fn content_length(&self) -> usize {
        self.content_length
    }

    pub fn header(&mut self, line: &str) -> Result<(), ParseResponseError> {
        debug!("<---- {}", line.trim());

        let mut parts = line.splitn(2, ':').map(|part| part.trim());
        let key = parts.next().ok_or(ParseResponseError::InvalidHeaderLine)?.to_owned();
        let value = parts.next().ok_or(ParseResponseError::InvalidHeaderLine)?.to_owned();

        if key.to_lowercase() == "content-length" {
            self.content_length = value.parse().map_err(|_| ParseResponseError::InvalidHeaderLine)?;
        }

        self.headers.push((key, value));

        Ok(())
    }

    pub fn body(self, data: Vec<u8>) -> Result<Response, RtspError> {
        let body = match String::from_utf8(data) {
            Ok(content) => {
                for line in content.lines() {
                    debug!("<---- {}", line);
                }

                content.into_bytes()
            },
            Err(error) => {
                let bytes = error.into_bytes();
                debug!("<---- ({} bytes)", bytes.len());
                bytes
            },
        };

        match self.status {
            200..=299 => Ok((self.headers, body)),
            400..=499 => Err(RtspError::Client { status: self.status, headers: self.headers, body }),
            500..=599 => Err(RtspError::Server { status: self.status, headers: self.headers, body }),
            _ => Err(RtspError::Unknown { status: self.status, headers: self.headers, body })
        }
    }
}
