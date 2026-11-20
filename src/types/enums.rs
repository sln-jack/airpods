use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, zvariant::Type, zvariant::Value)]
#[repr(u8)]
pub enum NoiseControlMode {
    Off = 0,
    NoiseCancellation = 1,
    Transparency = 2,
    Adaptive = 3,
}

impl fmt::Display for NoiseControlMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NoiseControlMode::Off => write!(f, "off"),
            NoiseControlMode::NoiseCancellation => write!(f, "anc"),
            NoiseControlMode::Transparency => write!(f, "transparency"),
            NoiseControlMode::Adaptive => write!(f, "adaptive"),
        }
    }
}

impl FromStr for NoiseControlMode {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "off" => Ok(NoiseControlMode::Off),
            "anc" | "noise_cancellation" => Ok(NoiseControlMode::NoiseCancellation),
            "transparency" => Ok(NoiseControlMode::Transparency),
            "adaptive" => Ok(NoiseControlMode::Adaptive),
            _ => Err(()),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Model {
    Unknown,
    AirPods1,
    AirPods2,
    AirPods3,
    AirPods4,
    AirPods4ANC,
    AirPodsPro,
    AirPodsPro2Lightning,
    AirPodsPro2USBC,
    AirPodsMaxLightning,
    AirPodsMaxUSBC,
}

impl fmt::Display for Model {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Model::Unknown => write!(f, "unknown"),
            Model::AirPods1 => write!(f, "airpods_1"),
            Model::AirPods2 => write!(f, "airpods_2"),
            Model::AirPods3 => write!(f, "airpods_3"),
            Model::AirPods4 => write!(f, "airpods_4"),
            Model::AirPods4ANC => write!(f, "airpods_4_anc"),
            Model::AirPodsPro => write!(f, "airpods_pro"),
            Model::AirPodsPro2Lightning => write!(f, "airpods_pro_2"),
            Model::AirPodsPro2USBC => write!(f, "airpods_pro_2_usbc"),
            Model::AirPodsMaxLightning => write!(f, "airpods_max"),
            Model::AirPodsMaxUSBC => write!(f, "airpods_max_usbc"),
        }
    }
}

impl Model {
    pub fn from_model_number(model_number: &str) -> Self {
        match model_number {
            "A1523" | "A1722" => Model::AirPods1,
            "A2032" | "A2031" => Model::AirPods2,
            "A2084" | "A2083" => Model::AirPodsPro,
            "A2096" => Model::AirPodsMaxLightning,
            "A3184" => Model::AirPodsMaxUSBC,
            "A2565" | "A2564" => Model::AirPods3,
            "A3047" | "A3048" | "A3049" => Model::AirPodsPro2USBC,
            "A2931" | "A2699" | "A2698" => Model::AirPodsPro2Lightning,
            "A3053" | "A3050" | "A3054" => Model::AirPods4,
            "A3056" | "A3055" | "A3057" => Model::AirPods4ANC,
            _ => Model::Unknown,
        }
    }

    pub fn is_headset(&self) -> bool {
        matches!(
            self,
            Model::AirPodsMaxLightning | Model::AirPodsMaxUSBC
        )
    }
}
