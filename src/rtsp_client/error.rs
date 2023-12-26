use std::error::Error;
use std::fmt::{self, Formatter, Display};
use std::string::FromUtf8Error;

use hex::FromHexError;

use super::response::ParseResponseError;

#[derive(Debug)]
pub enum RtspError {
    IoError(std::io::Error),
    FromHexError(FromHexError),
    ParseResponseError(ParseResponseError),
    DecodeResponseError(FromUtf8Error),
    ClientError { status: u16, headers: Vec<(String, String)>, body: Vec<u8> },
    ServerError { status: u16, headers: Vec<(String, String)>, body: Vec<u8> },
    UnknownError { status: u16, headers: Vec<(String, String)>, body: Vec<u8> },
}

impl Display for RtspError {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl Error for RtspError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            RtspError::IoError(source) => Some(source),
            RtspError::FromHexError(source) => Some(source),
            RtspError::ParseResponseError(source) => Some(source),
            RtspError::DecodeResponseError(source) => Some(source),
            _ => None,
        }
    }
}

impl From<FromHexError> for RtspError {
    fn from(error: FromHexError) -> Self {
        RtspError::FromHexError(error)
    }
}

impl From<FromUtf8Error> for RtspError {
    fn from(error: FromUtf8Error) -> Self {
        RtspError::DecodeResponseError(error)
    }
}

impl From<ParseResponseError> for RtspError {
    fn from(error: ParseResponseError) -> Self {
        RtspError::ParseResponseError(error)
    }
}

impl From<std::io::Error> for RtspError {
    fn from(error: std::io::Error) -> Self {
        RtspError::IoError(error)
    }
}
