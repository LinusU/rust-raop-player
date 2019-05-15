use crate::alac_encoder::AlacEncoder;
use crate::bindings::{malloc, free};

use std::fmt::{self, Formatter, Display};

pub enum Codec {
    ALAC(AlacEncoder),
    PCM { chunk_length: u32, sample_rate: u32, sample_size: u32, channels: u8 },
}

impl Codec {
    pub fn new(alac: bool, chunk_length: u32, sample_rate: u32, sample_size: u32, channels: u8) -> Codec {
        if alac {
            AlacEncoder::new(chunk_length, sample_rate, sample_size, channels).map(Codec::ALAC).unwrap()
        } else {
            Codec::PCM { chunk_length, sample_rate, sample_size, channels }
        }
    }

    pub fn chunk_length(&self) -> u32 {
        match self {
            Codec::ALAC(ref encoder) => encoder.chunk_length,
            Codec::PCM { chunk_length, .. } => *chunk_length,
        }
    }

    pub fn sample_rate(&self) -> u32 {
        match self {
            Codec::ALAC(ref encoder) => encoder.sample_rate,
            Codec::PCM { sample_rate, .. } => *sample_rate,
        }
    }

    pub fn sample_size(&self) -> u32 {
        match self {
            Codec::ALAC(ref encoder) => encoder.sample_size,
            Codec::PCM { sample_size, .. } => *sample_size,
        }
    }

    pub fn channels(&self) -> u8 {
        match self {
            Codec::ALAC(ref encoder) => encoder.channels,
            Codec::PCM { channels, .. } => *channels,
        }
    }

    pub fn sdp(&self) -> String {
        match self {
            Codec::ALAC(ref encoder) => {
                format!(
                    "m=audio 0 RTP/AVP 96\r\na=rtpmap:96 AppleLossless\r\na=fmtp:96 {}d 0 {} 40 10 14 {} 255 0 0 {}\r\n",
                    encoder.chunk_length,
                    encoder.sample_size,
                    encoder.channels,
                    encoder.sample_rate,
                )
            },
            Codec::PCM { sample_rate, sample_size, channels, .. } => {
                format!(
                    "m=audio 0 RTP/AVP 96\r\na=rtpmap:96 L{}/{}/{}\r\n",
                    sample_size,
                    sample_rate,
                    channels,
                )
            },
        }
    }

    pub fn encode_chunk(&self, sample: &mut [u8], frames: usize) -> Vec<u8> {
        let mut encoded: *mut u8 = std::ptr::null_mut();
        let mut size: i32 = 0;

        match self {
            Codec::ALAC(ref encoder) => {
                encoder.encode_chunk(sample, frames, &mut encoded, &mut size);
            },
            Codec::PCM { .. } => {
                size = (frames * 4) as i32;
                encoded = unsafe { malloc(frames * 4) as *mut u8 };
                for offset in (0..(size as usize)).step_by(4) {
                    unsafe {
                        *encoded.offset((offset + 0) as isize) = sample[offset + 1];
                        *encoded.offset((offset + 1) as isize) = sample[offset + 0];
                        *encoded.offset((offset + 2) as isize) = sample[offset + 3];
                        *encoded.offset((offset + 3) as isize) = sample[offset + 2];
                    }
                }
            },
        }

        let result = unsafe { std::slice::from_raw_parts(encoded, size as usize).to_vec() };

        unsafe { free(encoded as *mut std::ffi::c_void); }

        result
    }
}

impl Display for Codec {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self {
            Codec::ALAC(_) => write!(f, "ALAC"),
            Codec::PCM { .. } => write!(f, "PCM"),
        }
    }
}
