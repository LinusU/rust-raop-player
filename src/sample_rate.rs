use std::convert::TryFrom;
use std::fmt::{self, Formatter, Display};

#[derive(Debug, Clone, Copy, PartialOrd, PartialEq, Ord, Eq)]
pub enum SampleRate {
    Hz2000,
    Hz8000,
    Hz11025,
    Hz22050,
    Hz32000,
    Hz44100,
    Hz48000,
    Hz96000,
    Hz192000,
}

#[derive(Debug, Clone, Copy)]
pub enum IntoSampleRateError {
    InvalidSampleRate(u64),
}

impl From<SampleRate> for u64 {
    fn from(sample_rate: SampleRate) -> u64 {
        match sample_rate {
            SampleRate::Hz2000 => 2000,
            SampleRate::Hz8000 => 8000,
            SampleRate::Hz11025 => 11025,
            SampleRate::Hz22050 => 22050,
            SampleRate::Hz32000 => 32000,
            SampleRate::Hz44100 => 44100,
            SampleRate::Hz48000 => 48000,
            SampleRate::Hz96000 => 96000,
            SampleRate::Hz192000 => 192000,
        }
    }
}

impl TryFrom<u64> for SampleRate {
    type Error = IntoSampleRateError;

    fn try_from(value: u64) -> Result<SampleRate, Self::Error> {
        match value {
            2000 => Ok(SampleRate::Hz2000),
            8000 => Ok(SampleRate::Hz8000),
            11025 => Ok(SampleRate::Hz11025),
            22050 => Ok(SampleRate::Hz22050),
            32000 => Ok(SampleRate::Hz32000),
            44100 => Ok(SampleRate::Hz44100),
            48000 => Ok(SampleRate::Hz48000),
            96000 => Ok(SampleRate::Hz96000),
            192000 => Ok(SampleRate::Hz192000),
            value => Err(IntoSampleRateError::InvalidSampleRate(value)),
        }
    }
}

impl Display for SampleRate {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "{}", u64::from(*self))
    }
}
