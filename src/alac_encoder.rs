use crate::bindings::{alac_codec_s, alac_create_encoder, alac_delete_encoder, pcm_to_alac};

pub struct AlacEncoder {
    c_handle: *mut alac_codec_s,

    pub chunk_length: u32,
    pub sample_rate: u32,
    pub sample_size: u32,
    pub channels: u8,
}

impl AlacEncoder {
    pub fn new(chunk_length: u32, sample_rate: u32, sample_size: u32, channels: u8) -> Option<AlacEncoder> {
        let c_handle = unsafe { alac_create_encoder(chunk_length as i32, sample_rate as i32, sample_size as i32, channels as i32) };
        if c_handle.is_null() { None } else { Some(AlacEncoder { c_handle, chunk_length, sample_rate, sample_size, channels }) }
    }

    pub fn encode_chunk(&self, sample: &mut [u8], frames: usize, encoded: &mut *mut u8, size: &mut i32) -> bool {
        unsafe { pcm_to_alac(self.c_handle, &mut (*sample)[0], frames as i32, encoded, size) }
    }
}

impl Drop for AlacEncoder {
    fn drop(&mut self) {
        unsafe { alac_delete_encoder(self.c_handle); }
    }
}
