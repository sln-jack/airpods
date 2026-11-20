use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum BatteryStatus {
    Charging = 0x01,
    Discharging = 0x02,
    Disconnected = 0x04,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum BatteryComponent {
    Headset = 0x01,  // AirPods Max
    Right = 0x02,
    Left = 0x04,
    Case = 0x08,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ComponentBattery {
    pub level: i8,  // 0-100, or -1 if unavailable
    pub charging: bool,
    pub available: bool,
}

impl ComponentBattery {
    pub fn unavailable() -> Self {
        ComponentBattery {
            level: -1,
            charging: false,
            available: false,
        }
    }

    pub fn new(level: u8, charging: bool) -> Self {
        ComponentBattery {
            level: level as i8,
            charging,
            available: true,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct Battery {
    pub left: ComponentBattery,
    pub right: ComponentBattery,
    pub case_: ComponentBattery,
    pub headset: ComponentBattery,  // For AirPods Max

    // Which pod is primary (first in packet order)
    pub left_is_primary: bool,
}
