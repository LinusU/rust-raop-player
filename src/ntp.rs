use std::io::{self, Write};
use std::time::SystemTime;
use std::fmt::{self, Formatter, Display};

use byteorder::{BE, WriteBytesExt};

use crate::serialization::Serializable;

#[derive(Clone, Copy)]
pub struct NtpTime {
    pub seconds: u32,
    pub fraction: u32,
}

impl NtpTime {
    pub fn now() -> NtpTime {
        let unix = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap();

        NtpTime {
            seconds: (unix.as_secs() + 0x83AA7E80) as u32,
            fraction: (((unix.subsec_micros() as u64) << 32) / 1000000) as u32,
        }
    }

    pub fn from_timestamp(ts: u64, rate: u32) -> NtpTime {
        let ntp = (((ts as u64) << 16) / (rate as u64)) << 16;

        NtpTime {
            seconds: (ntp >> 32) as u32,
            fraction: ntp as u32,
        }
    }
}

impl Serializable for NtpTime {
    fn size(&self) -> usize {
        8
    }

    fn serialize(&self, writer: &mut Write) -> io::Result<()> {
        writer.write_u32::<BE>(self.seconds)?;
        writer.write_u32::<BE>(self.fraction)
    }
}

impl Display for NtpTime {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "{}.{}", self.seconds, self.fraction)
    }
}
