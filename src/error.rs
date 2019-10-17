
// #[derive(Debug)]
// pub enum RtspError {
//     Io(std::io::Error),
//     FromHex(hex::FromHexError),
//     OpenSsl(openssl::error::ErrorStack),
// }

// impl std::fmt::Display for RtspError {
//     fn fmt(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
//         match self {
//             RtspError::Io(ref err) => err.fmt(fmt),
//             RtspError::FromHex(ref err) => err.fmt(fmt),
//             RtspError::OpenSsl(ref err) => err.fmt(fmt),
//         }
//     }
// }

// impl std::error::Error for RtspError {
//     fn description(&self) -> &str {
//         match self {
//             RtspError::Io(ref err) => std::error::Error::description(err),
//             RtspError::FromHex(ref err) => std::error::Error::description(err),
//             RtspError::OpenSsl(ref err) => std::error::Error::description(err),
//         }
//     }

//     fn cause(&self) -> Option<&std::error::Error> {
//         match self {
//             RtspError::Io(ref err) => Some(err),
//             RtspError::FromHex(ref err) => Some(err),
//             RtspError::OpenSsl(ref err) => Some(err),
//         }
//     }
// }

// impl From<std::io::Error> for RtspError {
//     fn from(err: std::io::Error) -> RtspError {
//         RtspError::Io(err)
//     }
// }

// impl From<hex::FromHexError> for RtspError {
//     fn from(err: hex::FromHexError) -> RtspError {
//         RtspError::FromHex(err)
//     }
// }

// impl From<openssl::error::ErrorStack> for RtspError {
//     fn from(err: openssl::error::ErrorStack) -> RtspError {
//         RtspError::OpenSsl(err)
//     }
// }
