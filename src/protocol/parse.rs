use crate::protocol::packets::{self, headers};
use crate::types::{
    Battery, BatteryComponent, BatteryStatus, ComponentBattery, EarDetection, EarStatus,
    NoiseControlMode,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketType {
    Unknown,
    HandshakeAck,
    FeaturesAck,
    Battery,
    EarDetection,
    NoiseControlMode,
    Metadata,
    MagicKeys,
    ConversationalAwareness,
    HearingAid,
    OneBudAnc,
}

pub fn identify_packet(data: &[u8]) -> PacketType {
    if packets::starts_with(data, &headers::HANDSHAKE_ACK) {
        return PacketType::HandshakeAck;
    }
    if packets::starts_with(data, &headers::FEATURES_ACK) {
        return PacketType::FeaturesAck;
    }
    if packets::starts_with(data, &headers::BATTERY) {
        return PacketType::Battery;
    }
    if packets::starts_with(data, &headers::EAR_DETECTION) {
        return PacketType::EarDetection;
    }
    if packets::starts_with(data, &headers::NOISE_CONTROL) {
        return PacketType::NoiseControlMode;
    }
    if packets::starts_with(data, &headers::METADATA) {
        return PacketType::Metadata;
    }
    if packets::starts_with(data, &headers::MAGIC_KEYS) {
        return PacketType::MagicKeys;
    }
    if packets::starts_with(data, &headers::CONVERSATIONAL_AWARENESS) {
        return PacketType::ConversationalAwareness;
    }
    if packets::starts_with(data, &headers::HEARING_AID) {
        return PacketType::HearingAid;
    }
    if packets::starts_with(data, &headers::ONE_BUD_ANC) {
        return PacketType::OneBudAnc;
    }

    PacketType::Unknown
}

pub fn parse_battery(data: &[u8]) -> Option<Battery> {
    // Header: 04 00 04 00 04 00 [count] [components...]
    // Each component: [type] 01 [level] [status] 01
    if !packets::starts_with(data, &headers::BATTERY) {
        return None;
    }

    if data.len() < 7 {
        return None;
    }

    let count = data[6];
    let expected_size = 7 + (5 * count as usize);
    if count > 4 || data.len() != expected_size {
        return None;
    }

    let mut battery = Battery::default();
    let mut first_pod_is_left = true;
    let mut found_first_pod = false;

    for i in 0..count {
        let offset = 7 + (5 * i as usize);

        let type_ = data[offset];
        // Verify spacer bytes
        if data[offset + 1] != 0x01 || data[offset + 4] != 0x01 {
            return None;
        }

        let level = data[offset + 2];
        let status = data[offset + 3];

        let comp = ComponentBattery {
            level: level as i8,
            charging: status == BatteryStatus::Charging as u8,
            available: status != BatteryStatus::Disconnected as u8,
        };

        match type_ {
            t if t == BatteryComponent::Left as u8 => {
                battery.left = comp;
                if !found_first_pod {
                    first_pod_is_left = true;
                    found_first_pod = true;
                }
            }
            t if t == BatteryComponent::Right as u8 => {
                battery.right = comp;
                if !found_first_pod {
                    first_pod_is_left = false;
                    found_first_pod = true;
                }
            }
            t if t == BatteryComponent::Case as u8 => {
                battery.case_ = comp;
            }
            t if t == BatteryComponent::Headset as u8 => {
                battery.headset = comp;
            }
            _ => {}
        }
    }

    battery.left_is_primary = first_pod_is_left;
    Some(battery)
}

pub fn parse_ear_detection(data: &[u8]) -> Option<EarDetection> {
    // Header: 04 00 04 00 06 00 [primary] [secondary]
    if !packets::starts_with(data, &headers::EAR_DETECTION) {
        return None;
    }

    if data.len() < 8 {
        return None;
    }

    // Validate values
    if data[6] > 0x02 || data[7] > 0x02 {
        return None;
    }

    let detection = EarDetection {
        primary: match data[6] {
            0x00 => EarStatus::InEar,
            0x01 => EarStatus::NotInEar,
            0x02 => EarStatus::InCase,
            _ => return None,
        },
        secondary: match data[7] {
            0x00 => EarStatus::InEar,
            0x01 => EarStatus::NotInEar,
            0x02 => EarStatus::InCase,
            _ => return None,
        },
    };

    Some(detection)
}

pub fn parse_noise_control_mode(data: &[u8]) -> Option<NoiseControlMode> {
    // Header: 04 00 04 00 09 00 0D [mode] ...
    // Mode at byte 7: 0x01=off, 0x02=anc, 0x03=transparency, 0x04=adaptive
    if !packets::starts_with(data, &headers::NOISE_CONTROL) {
        return None;
    }

    if data.len() < 8 {
        return None;
    }

    // Mode value is 1-indexed in protocol, 0-indexed in enum
    let mode_value = data[7];
    if mode_value < 1 || mode_value > 4 {
        return None;
    }

    Some(match mode_value - 1 {
        0 => NoiseControlMode::Off,
        1 => NoiseControlMode::NoiseCancellation,
        2 => NoiseControlMode::Transparency,
        3 => NoiseControlMode::Adaptive,
        _ => return None,
    })
}

pub fn parse_bool_state(data: &[u8]) -> Option<bool> {
    // Control command format: [header 6 bytes][identifier][value]...
    // Value at byte 7: 0x01=enabled, 0x02=disabled
    if data.len() < 8 {
        return None;
    }

    match data[7] {
        0x01 => Some(true),
        0x02 => Some(false),
        _ => None,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetadataInfo {
    pub device_name: String,
    pub model_number: String,
    pub manufacturer: String,
}

pub fn parse_metadata(data: &[u8]) -> Option<MetadataInfo> {
    // Header: 04 00 04 00 1d [size bytes] [6 skip bytes] [null-terminated strings...]
    if !packets::starts_with(data, &headers::METADATA) {
        return None;
    }

    // Skip header (5 bytes) + size byte (1) + reserved (6) = 12 bytes minimum before strings
    let mut pos = headers::METADATA.len();
    if data.len() < pos + 7 {
        return None;
    }

    pos += 6; // Skip additional header bytes

    let extract_string = |pos: &mut usize| -> String {
        if *pos >= data.len() {
            return String::new();
        }

        let start = *pos;
        while *pos < data.len() && data[*pos] != 0 {
            *pos += 1;
        }

        let result = String::from_utf8_lossy(&data[start..*pos]).to_string();

        if *pos < data.len() {
            *pos += 1; // Skip null terminator
        }

        result
    };

    let device_name = extract_string(&mut pos);
    let model_number = extract_string(&mut pos);
    let manufacturer = extract_string(&mut pos);

    Some(MetadataInfo {
        device_name,
        model_number,
        manufacturer,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MagicKeys {
    pub irk: [u8; 16],
    pub enc_key: [u8; 16],
}

pub fn parse_magic_keys(data: &[u8]) -> Option<MagicKeys> {
    // Header: 04 00 04 00 31 00 02 [TLV blocks...]
    // TLV: [type] [len_hi] [len_lo] [reserved] [data...]
    // Type 0x01 = IRK (16 bytes), Type 0x04 = EncKey (16 bytes)
    if !packets::starts_with(data, &headers::MAGIC_KEYS) {
        return None;
    }

    if data.len() < 47 {
        // Header + 2 TLV blocks with 16-byte values
        return None;
    }

    let mut idx = headers::MAGIC_KEYS.len();

    let mut keys = MagicKeys {
        irk: [0; 16],
        enc_key: [0; 16],
    };

    // First TLV: IRK
    if data[idx] != 0x01 {
        return None;
    }
    idx += 1;

    let len1 = ((data[idx] as u16) << 8) | data[idx + 1] as u16;
    if len1 != 16 {
        return None;
    }
    idx += 3; // Skip length (2) + reserved (1)

    keys.irk.copy_from_slice(&data[idx..idx + 16]);
    idx += 16;

    // Second TLV: EncKey
    if data[idx] != 0x04 {
        return None;
    }
    idx += 1;

    let len2 = ((data[idx] as u16) << 8) | data[idx + 1] as u16;
    if len2 != 16 {
        return None;
    }
    idx += 3;

    keys.enc_key.copy_from_slice(&data[idx..idx + 16]);

    Some(keys)
}

pub fn parse_encrypted_battery(
    decrypted: &[u8; 16],
    left_is_primary: bool,
    pod_in_case: bool,
    is_headset: bool,
) -> Option<Battery> {
    // Decrypted packet format:
    // Byte 0: unknown
    // Byte 1: primary battery (bit 7 = charging, bits 0-6 = level 0-127, 127 = unknown)
    // Byte 2: secondary battery
    // Byte 3: case battery

    let format_battery = |byte: u8| -> (bool, i8) {
        let charging = (byte & 0x80) != 0;
        let level = (byte & 0x7F) as i8;
        let level = if level == 127 { -1 } else { level };
        (charging, level)
    };

    let mut battery = Battery::default();

    let primary_idx = if left_is_primary { 1 } else { 2 };
    let secondary_idx = if left_is_primary { 2 } else { 1 };

    let (left_charging, left_level) = format_battery(decrypted[primary_idx]);
    let (right_charging, right_level) = format_battery(decrypted[secondary_idx]);
    let (case_charging, case_level) = format_battery(decrypted[3]);

    if is_headset {
        // AirPods Max: find first available battery
        let batteries = [
            format_battery(decrypted[1]),
            format_battery(decrypted[2]),
            format_battery(decrypted[3]),
        ];

        for (charging, level) in batteries {
            if level != -1 {
                battery.headset.level = level;
                battery.headset.charging = charging;
                battery.headset.available = true;
                break;
            }
        }
    } else {
        battery.left.level = left_level;
        battery.left.charging = left_charging;
        battery.left.available = left_level != -1;

        battery.right.level = right_level;
        battery.right.charging = right_charging;
        battery.right.available = right_level != -1;

        if pod_in_case {
            battery.case_.level = case_level;
            battery.case_.charging = case_charging;
            battery.case_.available = case_level != -1;
        }
    }

    battery.left_is_primary = left_is_primary;
    Some(battery)
}
