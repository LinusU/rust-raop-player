use std::fmt::{self, Formatter, Display};
use std::num::ParseIntError;
use std::ops::{Add, AddAssign, Div, Sub};
use std::str::FromStr;
use std::time::Duration;

use crate::sample_rate::SampleRate;

#[derive(Clone, Copy, PartialOrd, PartialEq, Ord, Eq)]
pub struct Frames(u64);

fn scale(value: u64, max: u64) -> u32 {
    assert!(max < (u32::MAX as u64));
    (value * (u32::MAX as u64) / max) as u32
}

impl Frames {
    pub const fn new(value: u64) -> Frames {
        Frames(value)
    }

    pub const fn as_usize(self, frame_size: usize) -> usize {
        (self.0 as usize) * frame_size
    }

    pub const fn from_usize(size: usize, frame_size: usize) -> Frames {
        Frames((size / frame_size) as u64)
    }
}

impl From<Frames> for u64 {
    fn from(frames: Frames) -> u64 {
        frames.0
    }
}

impl From<u64> for Frames {
    fn from(value: u64) -> Frames {
        Frames(value)
    }
}

impl Add for Frames {
    type Output = Frames;

    fn add(self, other: Frames) -> Frames {
        Frames(self.0 + other.0)
    }
}

impl AddAssign for Frames {
    fn add_assign(&mut self, other: Self) {
        self.0 += other.0
    }
}

impl Div<SampleRate> for Frames {
    type Output = Duration;

    #[allow(clippy::suspicious_arithmetic_impl)]
    fn div(self, other: SampleRate) -> Duration {
        let sample_rate = u64::from(other);
        Duration::new(self.0 / sample_rate, scale(self.0 % sample_rate, sample_rate - 1))
    }
}

impl Sub for Frames {
    type Output = Frames;

    fn sub(self, other: Frames) -> Frames {
        Frames(self.0 - other.0)
    }
}

impl FromStr for Frames {
    type Err = ParseIntError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        s.parse::<u64>().map(Frames)
    }
}

impl Display for Frames {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}
