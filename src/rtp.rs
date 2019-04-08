use crate::bindings::{ntp_t};
use crate::serialization::Serializable;
use std::io::{self, Write};

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

impl Serializable for RtpAudioPacket {
    fn size(&self) -> usize {
        4 + 8 + self.data.len()
    }

    fn serialize(&self, writer: &mut Write) -> io::Result<()> {
        writer.write_u8(self.header.proto)?;
        writer.write_u8(self.header.type_)?;
        writer.write_u16::<BE>(self.header.seq)?;

        writer.write_u32::<BE>(self.timestamp)?;
        writer.write_u32::<BE>(self.ssrc)?;

        writer.write_all(&self.data)
    }
}

pub struct RtpAudioRetransmissionPacket<'a> {
    pub packet: &'a RtpAudioPacket,
}

impl<'a> RtpAudioRetransmissionPacket<'a> {
    pub fn wrap(packet: &RtpAudioPacket) -> RtpAudioRetransmissionPacket {
        RtpAudioRetransmissionPacket { packet }
    }
}

impl<'a> Serializable for RtpAudioRetransmissionPacket<'a> {
    fn size(&self) -> usize {
        4 + self.packet.size()
    }

    fn serialize(&self, writer: &mut Write) -> io::Result<()> {
        // Retransmission header:
        writer.write_u8(0x80)?;
        writer.write_u8(0x56 | 0x80)?;
        writer.write_u8(0x00)?;
        writer.write_u8(0x01)?;

        self.packet.serialize(writer)
    }
}
