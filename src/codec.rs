use std::fmt::{self, Formatter, Display};

use alac_encoder::{AlacEncoder, FormatDescription, MAX_ESCAPE_HEADER_BYTES};

pub enum Codec {
    ALAC(AlacEncoder, FormatDescription),
    PCM { chunk_length: u32, sample_rate: u32, sample_size: u32, channels: u8 },
}

impl Codec {
    pub fn new(alac: bool, chunk_length: u32, sample_rate: u32, sample_size: u32, channels: u8) -> Codec {
        if alac {
            assert_eq!(sample_size, 16);
            let input_format = FormatDescription::pcm::<i16>(sample_rate as f64, channels as u32);
            let output_format = FormatDescription::alac(sample_rate as f64, chunk_length, channels as u32);
            Codec::ALAC(AlacEncoder::new(&output_format), input_format)
        } else {
            Codec::PCM { chunk_length, sample_rate, sample_size, channels }
        }
    }

    pub fn chunk_length(&self) -> u32 {
        match self {
            Codec::ALAC(ref encoder, _) => encoder.frames() as u32,
            Codec::PCM { chunk_length, .. } => *chunk_length,
        }
    }

    pub fn sample_rate(&self) -> u32 {
        match self {
            Codec::ALAC(ref encoder, _) => encoder.sample_rate() as u32,
            Codec::PCM { sample_rate, .. } => *sample_rate,
        }
    }

    pub fn sample_size(&self) -> u32 {
        match self {
            Codec::ALAC(ref encoder, _) => encoder.bit_depth() as u32,
            Codec::PCM { sample_size, .. } => *sample_size,
        }
    }

    pub fn channels(&self) -> u8 {
        match self {
            Codec::ALAC(ref encoder, _) => encoder.channels() as u8,
            Codec::PCM { channels, .. } => *channels,
        }
    }

    pub fn sdp(&self) -> String {
        match self {
            Codec::ALAC(ref encoder, _) => {
                format!(
                    "m=audio 0 RTP/AVP 96\r\na=rtpmap:96 AppleLossless\r\na=fmtp:96 {}d 0 {} 40 10 14 {} 255 0 0 {}\r\n",
                    encoder.frames(),
                    encoder.bit_depth(),
                    encoder.channels(),
                    encoder.sample_rate(),
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

    pub fn encode_chunk(&mut self, sample: &[u8]) -> Vec<u8> {
        match self {
            Codec::ALAC(ref mut encoder, ref input_format) => {
                let max_size = sample.len() + MAX_ESCAPE_HEADER_BYTES;
                let mut encoded = Vec::with_capacity(max_size);

                unsafe { encoded.set_len(max_size); }
                let size = encoder.encode(input_format, sample, &mut encoded);
                unsafe { encoded.set_len(size); }

                encoded
            },
            Codec::PCM { .. } => {
                let size = sample.len();
                let mut encoded = Vec::with_capacity(size);
                unsafe { encoded.set_len(size); }

                for offset in (0..(size as usize)).step_by(4) {
                    encoded[offset + 0] = sample[offset + 1];
                    encoded[offset + 1] = sample[offset + 0];
                    encoded[offset + 2] = sample[offset + 3];
                    encoded[offset + 3] = sample[offset + 2];
                }

                encoded
            },
        }
    }
}

impl Display for Codec {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self {
            Codec::ALAC(_, _) => write!(f, "ALAC"),
            Codec::PCM { .. } => write!(f, "PCM"),
        }
    }
}
