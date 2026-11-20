use crate::types::NoiseControlMode;

// Control command header: 04 00 04 00 09 00
const HEADER: [u8; 6] = [0x04, 0x00, 0x04, 0x00, 0x09, 0x00];

// Create a control command packet
// Format: [HEADER][identifier][data1][data2][data3][data4]
fn create(identifier: u8, data1: u8, data2: u8, data3: u8, data4: u8) -> Vec<u8> {
    vec![
        HEADER[0], HEADER[1], HEADER[2], HEADER[3], HEADER[4], HEADER[5],
        identifier, data1, data2, data3, data4,
    ]
}

// Command identifiers
pub mod ids {
    pub const NOISE_CONTROL: u8 = 0x0D;
    pub const ONE_BUD_ANC: u8 = 0x1B;
    pub const VOLUME_SWIPE: u8 = 0x25;
    pub const ADAPTIVE_VOLUME: u8 = 0x26;
    pub const CONVERSATIONAL_AWARENESS: u8 = 0x28;
    pub const HEARING_AID: u8 = 0x2C;
    pub const ADAPTIVE_NOISE: u8 = 0x2E;
    pub const HEARING_ASSIST: u8 = 0x33;
    pub const ALLOW_OFF_OPTION: u8 = 0x34;
}

// Noise control mode commands
pub mod noise_control {
    use super::*;

    pub fn off() -> Vec<u8> {
        create(ids::NOISE_CONTROL, 0x01, 0x00, 0x00, 0x00)
    }

    pub fn anc() -> Vec<u8> {
        create(ids::NOISE_CONTROL, 0x02, 0x00, 0x00, 0x00)
    }

    pub fn transparency() -> Vec<u8> {
        create(ids::NOISE_CONTROL, 0x03, 0x00, 0x00, 0x00)
    }

    pub fn adaptive() -> Vec<u8> {
        create(ids::NOISE_CONTROL, 0x04, 0x00, 0x00, 0x00)
    }

    pub fn for_mode(mode: NoiseControlMode) -> Vec<u8> {
        match mode {
            NoiseControlMode::Off => off(),
            NoiseControlMode::NoiseCancellation => anc(),
            NoiseControlMode::Transparency => transparency(),
            NoiseControlMode::Adaptive => adaptive(),
        }
    }
}

// Conversational awareness commands
pub mod conversational_awareness {
    use super::*;

    pub fn enable() -> Vec<u8> {
        create(ids::CONVERSATIONAL_AWARENESS, 0x01, 0x00, 0x00, 0x00)
    }

    pub fn disable() -> Vec<u8> {
        create(ids::CONVERSATIONAL_AWARENESS, 0x02, 0x00, 0x00, 0x00)
    }
}

// One bud ANC mode
pub mod one_bud_anc {
    use super::*;

    pub fn enable() -> Vec<u8> {
        create(ids::ONE_BUD_ANC, 0x01, 0x00, 0x00, 0x00)
    }

    pub fn disable() -> Vec<u8> {
        create(ids::ONE_BUD_ANC, 0x02, 0x00, 0x00, 0x00)
    }
}

// Hearing aid
pub mod hearing_aid {
    use super::*;

    pub fn enable() -> Vec<u8> {
        create(ids::HEARING_AID, 0x01, 0x01, 0x00, 0x00)
    }

    pub fn disable() -> Vec<u8> {
        create(ids::HEARING_AID, 0x02, 0x02, 0x00, 0x00)
    }
}

// Adaptive noise level (0-100)
pub mod adaptive_noise {
    use super::*;

    pub fn set_level(level: u8) -> Vec<u8> {
        create(ids::ADAPTIVE_NOISE, level, 0x00, 0x00, 0x00)
    }
}

// Rename device
pub mod rename {
    pub fn set_name(name: &str) -> Vec<u8> {
        // Header: 04 00 04 00 1A 00 01 [length] 00 [name bytes]
        let mut packet = vec![0x04, 0x00, 0x04, 0x00, 0x1A, 0x00, 0x01];
        packet.push(name.len() as u8);
        packet.push(0x00);
        packet.extend_from_slice(name.as_bytes());
        packet
    }
}
