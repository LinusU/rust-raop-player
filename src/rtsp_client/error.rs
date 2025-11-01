use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::string::FromUtf8Error;

use hex::FromHexError;

use super::response::ParseResponseError;

#[derive(Debug)]
pub enum RtspError {
    Io(std::io::Error),
    FromHex(FromHexError),
    ParseResponse(ParseResponseError),
    DecodeResponse(FromUtf8Error),
    Client { status: u16, headers: Vec<(String, String)>, body: Vec<u8> },
    Server { status: u16, headers: Vec<(String, String)>, body: Vec<u8> },
    Unknown { status: u16, headers: Vec<(String, String)>, body: Vec<u8> },
}

impl Display for RtspError {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl Error for RtspError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            RtspError::Io(source) => Some(source),
            RtspError::FromHex(source) => Some(source),
            RtspError::ParseResponse(source) => Some(source),
            RtspError::DecodeResponse(source) => Some(source),
            _ => None,
        }
    }
}

impl From<FromHexError> for RtspError {
    fn from(error: FromHexError) -> Self {
        RtspError::FromHex(error)
    }
}

impl From<FromUtf8Error> for RtspError {
    fn from(error: FromUtf8Error) -> Self {
        RtspError::DecodeResponse(error)
    }
}

impl From<ParseResponseError> for RtspError {
    fn from(error: ParseResponseError) -> Self {
        RtspError::ParseResponse(error)
    }
}

impl From<std::io::Error> for RtspError {
    fn from(error: std::io::Error) -> Self {
        RtspError::Io(error)
    }
}
