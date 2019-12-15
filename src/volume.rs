#[derive(Clone, Copy)]
pub enum Volume {
    Value(f32),
    Muted,
}

const VOLUME_MIN: f32 = -30.0;
const VOLUME_MAX: f32 = 0.0;

impl Volume {
    pub fn from_percent(percent: u8) -> Volume {
        match percent {
            0 => Volume::Muted,
            1..=99 => Volume::Value(VOLUME_MIN + ((VOLUME_MAX - VOLUME_MIN) * (percent as f32)) / 100.0),
            100..=255 => Volume::Value(VOLUME_MAX),
        }
    }

    pub fn into_f32(self) -> f32 {
        match self {
            Volume::Value(value) => value,
            Volume::Muted => -144.0,
        }
    }
}
