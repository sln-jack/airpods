use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum EarStatus {
    InEar = 0x00,
    NotInEar = 0x01,
    InCase = 0x02,
    Unknown = 0xFF,
}

impl Default for EarStatus {
    fn default() -> Self {
        EarStatus::Unknown
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct EarDetection {
    pub primary: EarStatus,
    pub secondary: EarStatus,
}

impl EarDetection {
    pub fn primary_in_ear(&self) -> bool {
        self.primary == EarStatus::InEar
    }

    pub fn secondary_in_ear(&self) -> bool {
        self.secondary == EarStatus::InEar
    }

    pub fn any_in_ear(&self) -> bool {
        self.primary_in_ear() || self.secondary_in_ear()
    }

    pub fn any_in_case(&self) -> bool {
        self.primary == EarStatus::InCase || self.secondary == EarStatus::InCase
    }
}
