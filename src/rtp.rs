use crate::frames::Frames;
use crate::ntp::NtpTime;
use crate::sample_rate::SampleRate;
use crate::serialization::{Deserializable, Serializable};

use std::io::{self, Read, Write};

use byteorder::{BE, ReadBytesExt, WriteBytesExt};

const RETRANSMISSION_HEADER: RtpHeader = RtpHeader { proto: 0x80, type_: 0x56 | 0x80, seq: 1 };

#[derive(Debug)]
pub struct RtpHeader {
    pub proto: u8,
    pub type_: u8,
    pub seq: u16,
}

impl Deserializable for RtpHeader {
    const SIZE: usize = 4;

    fn deserialize(reader: &mut dyn Read) -> io::Result<RtpHeader> {
        let proto = reader.read_u8()?;
        let type_ = reader.read_u8()?;
        let seq = reader.read_u16::<BE>()?;

        Ok(RtpHeader { proto, type_, seq })
    }
}

impl Serializable for RtpHeader {
    fn size(&self) -> usize {
        RtpHeader::SIZE
    }

    fn serialize(&self, writer: &mut dyn Write) -> io::Result<()> {
        writer.write_u8(self.proto)?;
        writer.write_u8(self.type_)?;
        writer.write_u16::<BE>(self.seq)
    }
}

pub struct RtpSyncPacket {
    pub header: RtpHeader,
    pub rtp_timestamp_latency: u32,
    pub curr_time: NtpTime,
    pub rtp_timestamp: u32,
}

impl RtpSyncPacket {
    pub fn build(timestamp: Frames, sample_rate: SampleRate, latency: Frames, first: bool) -> RtpSyncPacket {
        RtpSyncPacket {
            header: RtpHeader {
                proto: 0x80 | if first { 0x10 } else { 0x00 },
                type_: 0x54 | 0x80,
                // seems that seq=7 shall be forced
                seq: 7,
            },

            // set the NTP time
            curr_time: NtpTime::from_timestamp(timestamp, sample_rate),

            // The DAC time is synchronized with gettime_ms(), minus the latency.
            rtp_timestamp: u64::from(timestamp) as u32,
            rtp_timestamp_latency: if latency > timestamp { 0 } else { u64::from(timestamp - latency) as u32 },
        }
    }
}

impl Serializable for RtpSyncPacket {
    fn size(&self) -> usize {
        self.header.size() + 16
    }

    fn serialize(&self, writer: &mut dyn Write) -> io::Result<()> {
        self.header.serialize(writer)?;
        writer.write_u32::<BE>(self.rtp_timestamp_latency)?;
        self.curr_time.serialize(writer)?;
        writer.write_u32::<BE>(self.rtp_timestamp)
    }
}

pub struct RtpAudioPacket {
    pub header: RtpHeader,
    pub timestamp: Frames,
    pub ssrc: u32,
    pub data: Vec<u8>,
}

impl Serializable for RtpAudioPacket {
    fn size(&self) -> usize {
        self.header.size() + 8 + self.data.len()
    }

    fn serialize(&self, writer: &mut dyn Write) -> io::Result<()> {
        self.header.serialize(writer)?;
        writer.write_u32::<BE>(u64::from(self.timestamp) as u32)?;
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
        RETRANSMISSION_HEADER.size() + self.packet.size()
    }

    fn serialize(&self, writer: &mut dyn Write) -> io::Result<()> {
        RETRANSMISSION_HEADER.serialize(writer)?;
        self.packet.serialize(writer)
    }
}

#[derive(Debug)]
pub struct RtpLostPacket {
    header: RtpHeader,
    pub seq_number: u16,
    pub n: u16,
}

impl Deserializable for RtpLostPacket {
    const SIZE: usize = RtpHeader::SIZE + 2 + 2;

    fn deserialize(reader: &mut dyn Read) -> io::Result<RtpLostPacket> {
        let header = RtpHeader::deserialize(reader)?;
        let seq_number = reader.read_u16::<BE>()?;
        let n = reader.read_u16::<BE>()?;

        Ok(RtpLostPacket { header, seq_number, n })
    }
}

pub struct RtpTimePacket {
    pub header: RtpHeader,
    pub dummy: u32,
    pub ref_time: NtpTime,
    pub recv_time: NtpTime,
    pub send_time: NtpTime,
}

impl Deserializable for RtpTimePacket {
    const SIZE: usize = RtpHeader::SIZE + 4 + NtpTime::SIZE + NtpTime::SIZE + NtpTime::SIZE;

    fn deserialize(reader: &mut dyn Read) -> io::Result<RtpTimePacket> {
        let header = RtpHeader::deserialize(reader)?;
        let dummy = reader.read_u32::<BE>()?;
        let ref_time = NtpTime::deserialize(reader)?;
        let recv_time = NtpTime::deserialize(reader)?;
        let send_time = NtpTime::deserialize(reader)?;

        Ok(RtpTimePacket { header, dummy, ref_time, recv_time, send_time })
    }
}

impl Serializable for RtpTimePacket {
    fn size(&self) -> usize {
        RtpTimePacket::SIZE
    }

    fn serialize(&self, writer: &mut dyn Write) -> io::Result<()> {
        self.header.serialize(writer)?;
        writer.write_u32::<BE>(self.dummy)?;
        self.ref_time.serialize(writer)?;
        self.recv_time.serialize(writer)?;
        self.send_time.serialize(writer)
    }
}
