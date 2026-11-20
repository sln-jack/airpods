use super::{battery::Battery, ear_detection::EarDetection, enums::{Model, NoiseControlMode}};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct DeviceState {
    // Connection
    pub connected: bool,
    pub mac_address: String,

    // Identity
    pub device_name: String,
    pub model_number: String,
    pub model: Model,

    // State
    pub noise_control_mode: NoiseControlMode,
    pub battery: Battery,
    pub ear_detection: EarDetection,

    // Magic pairing keys (16 bytes each)
    pub irk: [u8; 16],
    pub enc_key: [u8; 16],
    pub has_magic_keys: bool,
}

impl Default for Model {
    fn default() -> Self {
        Model::Unknown
    }
}

impl Default for NoiseControlMode {
    fn default() -> Self {
        NoiseControlMode::Off
    }
}
