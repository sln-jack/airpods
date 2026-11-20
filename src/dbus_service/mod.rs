use crate::types::{DeviceState, NoiseControlMode};
use anyhow::{Context, Result};
use std::str::FromStr;
use std::sync::Arc;
use tokio::sync::RwLock;
use zbus::Connection;

pub const SERVICE_NAME: &str = "com.apple.Airpods";
pub const OBJECT_PATH: &str = "/com/apple/Airpods";

#[derive(Clone)]
pub struct AirpodsService {
    state: Arc<RwLock<DeviceState>>,
    callbacks: Arc<Callbacks>,
}

#[derive(Default)]
pub struct Callbacks {
    pub on_pair: Option<Box<dyn Fn() + Send + Sync>>,
    pub on_connect: Option<Box<dyn Fn() + Send + Sync>>,
    pub on_disconnect: Option<Box<dyn Fn() + Send + Sync>>,
    pub on_set_noise_control: Option<Box<dyn Fn(NoiseControlMode) + Send + Sync>>,
}

#[zbus::dbus_interface(name = "com.apple.Airpods")]
impl AirpodsService {
    async fn pair(&self) -> zbus::fdo::Result<()> {
        tracing::info!("dbus: Pair() called");
        if let Some(ref callback) = self.callbacks.on_pair {
            callback();
        }
        Ok(())
    }

    async fn connect(&self) -> zbus::fdo::Result<()> {
        tracing::info!("dbus: Connect() called");
        if let Some(ref callback) = self.callbacks.on_connect {
            callback();
        }
        Ok(())
    }

    async fn disconnect(&self) -> zbus::fdo::Result<()> {
        tracing::info!("dbus: Disconnect() called");
        if let Some(ref callback) = self.callbacks.on_disconnect {
            callback();
        }
        Ok(())
    }

    async fn set_noise_control(&self, mode: String) -> zbus::fdo::Result<()> {
        tracing::info!("dbus: SetNoiseControl({}) called", mode);
        if let Ok(noise_mode) = NoiseControlMode::from_str(&mode) {
            if let Some(ref callback) = self.callbacks.on_set_noise_control {
                callback(noise_mode);
            }
        }
        Ok(())
    }

    #[dbus_interface(property, name = "Connected")]
    async fn connected(&self) -> bool {
        self.state.read().await.connected
    }

    #[dbus_interface(property, name = "NoiseControlMode")]
    async fn noise_control_mode(&self) -> String {
        self.state.read().await.noise_control_mode.to_string()
    }

    #[dbus_interface(property, name = "DeviceName")]
    async fn device_name(&self) -> String {
        self.state.read().await.device_name.clone()
    }

    #[dbus_interface(property, name = "Model")]
    async fn model(&self) -> String {
        self.state.read().await.model.to_string()
    }

    #[dbus_interface(property, name = "BatteryLeft")]
    async fn battery_left(&self) -> i32 {
        self.state.read().await.battery.left.level as i32
    }

    #[dbus_interface(property, name = "BatteryRight")]
    async fn battery_right(&self) -> i32 {
        self.state.read().await.battery.right.level as i32
    }

    #[dbus_interface(property, name = "BatteryCase")]
    async fn battery_case(&self) -> i32 {
        self.state.read().await.battery.case_.level as i32
    }

    #[dbus_interface(property, name = "ChargingLeft")]
    async fn charging_left(&self) -> bool {
        self.state.read().await.battery.left.charging
    }

    #[dbus_interface(property, name = "ChargingRight")]
    async fn charging_right(&self) -> bool {
        self.state.read().await.battery.right.charging
    }

    #[dbus_interface(property, name = "ChargingCase")]
    async fn charging_case(&self) -> bool {
        self.state.read().await.battery.case_.charging
    }

    #[dbus_interface(property, name = "LeftInEar")]
    async fn left_in_ear(&self) -> bool {
        let state = self.state.read().await;
        if state.battery.left_is_primary {
            state.ear_detection.primary_in_ear()
        } else {
            state.ear_detection.secondary_in_ear()
        }
    }

    #[dbus_interface(property, name = "RightInEar")]
    async fn right_in_ear(&self) -> bool {
        let state = self.state.read().await;
        if state.battery.left_is_primary {
            state.ear_detection.secondary_in_ear()
        } else {
            state.ear_detection.primary_in_ear()
        }
    }
}

impl AirpodsService {
    pub fn new(state: Arc<RwLock<DeviceState>>, callbacks: Callbacks) -> Self {
        Self {
            state,
            callbacks: Arc::new(callbacks),
        }
    }

    pub async fn update_state(&self, new_state: DeviceState) -> Result<()> {
        let mut state = self.state.write().await;
        *state = new_state;
        Ok(())
    }
}

pub async fn start_service(
    state: Arc<RwLock<DeviceState>>,
    callbacks: Callbacks,
) -> Result<Connection> {
    let service = AirpodsService::new(state, callbacks);

    let conn = zbus::connection::Builder::session()?
        .name(SERVICE_NAME)?
        .serve_at(OBJECT_PATH, service)?
        .build()
        .await
        .context("Failed to build D-Bus connection")?;

    tracing::info!("D-Bus service started: {}", SERVICE_NAME);

    Ok(conn)
}
