use crate::codec::Codec;
use crate::crypto::Crypto;
use crate::frames::Frames;
use crate::raop_client::MAX_SAMPLES_PER_CHUNK;
use crate::sample_rate::SampleRate;

pub struct RaopParams {
    pub(super) auth: bool,
    pub(super) codec: Codec,
    pub(super) crypto: Crypto,
    pub(super) desired_latency: Frames,
    pub(super) et: Option<String>,
    pub(super) md: Option<String>,
    pub(super) secret: Option<String>,
}

impl Default for RaopParams {
    fn default() -> Self {
        RaopParams {
            auth: false,
            codec: Codec::new(false, MAX_SAMPLES_PER_CHUNK, SampleRate::Hz44100, 16, 2),
            crypto: Crypto::new(false),
            desired_latency: Frames::new(44100),
            et: None,
            md: None,
            secret: None,
        }
    }
}

impl RaopParams {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set_codec(&mut self, codec: Codec) {
        self.codec = codec;
    }

    pub fn set_crypto(&mut self, crypto: Crypto) {
        self.crypto = crypto;
    }

    pub fn set_desired_latency(&mut self, desired_latency: Frames) {
        self.desired_latency = desired_latency;
    }

    pub fn set_et(&mut self, et: String) {
        self.et = Option::from(et);
    }

    pub fn set_md(&mut self, md: String) {
        self.md = Option::from(md);
    }
}
