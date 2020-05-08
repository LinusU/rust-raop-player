use std::error::Error;
use std::fmt::{self, Formatter, Display};
use std::num::ParseIntError;
use std::string::FromUtf8Error;

use log::debug;

use super::RtspError;

pub type Response = (Vec<(String, String)>, String);

#[derive(Debug)]
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
        let content_type = self.headers.iter().find(|header| header.0.to_lowercase() == "content-type").map(|header| header.1.as_str());

        let content = String::from("");
        if let Some(content_type) = content_type {
            if content_type == "application/octet-stream" {
                debug!("<---- binary data");
            } else {
                let content = String::from_utf8(data)?;

                for line in content.lines() {
                    debug!("<---- {}", line);
                }
            }
        }

        match self.status {
            200..=299 => Ok((self.headers, content)),
            400..=499 => Err(RtspError::ClientError { status: self.status, headers: self.headers, body: content }),
            500..=599 => Err(RtspError::ServerError { status: self.status, headers: self.headers, body: content }),
            _ => Err(RtspError::UnknownError { status: self.status, headers: self.headers, body: content })
        }
    }
}
