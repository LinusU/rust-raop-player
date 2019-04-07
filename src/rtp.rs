use crate::bindings::{ntp_t};

use byteorder::{BE, WriteBytesExt};

pub struct RtpHeader {
    pub proto: u8,
    pub type_: u8,
    pub seq: u16,
}

pub struct RtpSyncPacket {
    pub header: RtpHeader,
    pub rtp_timestamp_latency: u32,
    pub curr_time: ntp_t,
    pub rtp_timestamp: u32,
}

pub struct RtpAudioPacket {
    pub header: RtpHeader,
    pub timestamp: u32,
    pub ssrc: u32,
    pub data: Vec<u8>,
}

impl RtpAudioPacket {
    pub fn size(&self) -> usize {
        4 + 8 + self.data.len()
    }

    pub fn as_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::<u8>::with_capacity(self.size());

        bytes.push(self.header.proto);
        bytes.push(self.header.type_);
        bytes.write_u16::<BE>(self.header.seq).unwrap();

        bytes.write_u32::<BE>(self.timestamp).unwrap();
        bytes.write_u32::<BE>(self.ssrc).unwrap();

        bytes.extend_from_slice(&self.data);

        bytes
    }

    pub fn as_retransmission_packet_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::<u8>::with_capacity(self.size());

        // Retransmission header:
        bytes.push(0x80);
        bytes.push(0x56 | 0x80);
        bytes.push(0x00);
        bytes.push(0x01);

        bytes.push(self.header.proto);
        bytes.push(self.header.type_);
        bytes.write_u16::<BE>(self.header.seq).unwrap();

        bytes.write_u32::<BE>(self.timestamp).unwrap();
        bytes.write_u32::<BE>(self.ssrc).unwrap();

        bytes.extend_from_slice(&self.data);

        bytes
    }
}
