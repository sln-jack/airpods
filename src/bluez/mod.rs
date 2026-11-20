pub mod a2dp;

use anyhow::{Context, Result};
use bluer::Address;
use bluer::Uuid;
use futures::StreamExt;

pub const AIRPODS_UUID: Uuid = Uuid::from_u128(0x74ec2172_0bad_4d01_8f77_997b2be0722a);

#[derive(Debug, Clone)]
pub struct DeviceInfo {
    pub address: Address,
    pub name: String,
    pub connected: bool,
    pub paired: bool,
}

pub fn is_airpods_name(name: &str) -> bool {
    name.to_lowercase().contains("airpods")
}

async fn is_airpods_device(device: &bluer::Device) -> bool {
    // Check UUIDs
    if let Ok(Some(uuids)) = device.uuids().await {
        if uuids.contains(&AIRPODS_UUID) {
            return true;
        }
    }

    // Check name
    if let Ok(Some(name)) = device.name().await {
        if is_airpods_name(&name) {
            return true;
        }
    }

    false
}

pub async fn get_default_adapter(session: &bluer::Session) -> Result<bluer::Adapter> {
    session
        .default_adapter()
        .await
        .context("Failed to get default Bluetooth adapter")
}

pub async fn find_paired_airpods(adapter: &bluer::Adapter) -> Result<Vec<DeviceInfo>> {
    let mut devices = Vec::new();

    let addresses = adapter.device_addresses().await?;

    for addr in addresses {
        let device = adapter.device(addr)?;

        if !is_airpods_device(&device).await {
            continue;
        }

        if let Ok(true) = device.is_paired().await {
            let name = device.name().await?.unwrap_or_else(|| "Unknown".to_string());
            let connected = device.is_connected().await.unwrap_or(false);

            devices.push(DeviceInfo {
                address: addr,
                name,
                connected,
                paired: true,
            });
        }
    }

    Ok(devices)
}

pub async fn find_connected_airpods(adapter: &bluer::Adapter) -> Result<Option<DeviceInfo>> {
    let addresses = adapter.device_addresses().await?;

    for addr in addresses {
        let device = adapter.device(addr)?;

        if !is_airpods_device(&device).await {
            continue;
        }

        if let Ok(true) = device.is_connected().await {
            let name = device.name().await?.unwrap_or_else(|| "Unknown".to_string());
            let paired = device.is_paired().await.unwrap_or(false);

            return Ok(Some(DeviceInfo {
                address: addr,
                name,
                connected: true,
                paired,
            }));
        }
    }

    Ok(None)
}

pub async fn find_unpaired_airpods(adapter: &bluer::Adapter) -> Result<Vec<DeviceInfo>> {
    let mut devices = Vec::new();

    let addresses = adapter.device_addresses().await?;

    for addr in addresses {
        let device = adapter.device(addr)?;

        if !is_airpods_device(&device).await {
            continue;
        }

        if let Ok(false) = device.is_paired().await {
            let name = device.name().await?.unwrap_or_else(|| "Unknown".to_string());
            let connected = device.is_connected().await.unwrap_or(false);

            devices.push(DeviceInfo {
                address: addr,
                name,
                connected,
                paired: false,
            });
        }
    }

    Ok(devices)
}

pub async fn start_discovery(_adapter: &bluer::Adapter) -> Result<()> {
    tracing::info!("Starting BLE discovery...");
    // Discovery is started automatically when we call discover_devices()
    // in bluer 0.17
    Ok(())
}

pub async fn stop_discovery(_adapter: &bluer::Adapter) -> Result<()> {
    tracing::info!("Stopping BLE discovery...");
    // Discovery stops when the stream from discover_devices() is dropped
    Ok(())
}

/// Yields whenever a device connects or disconnects.
pub async fn connection_changes() -> Result<impl futures::Stream<Item = ()>> {
    use std::collections::HashMap;
    use zbus::zvariant::Value;

    let conn = zbus::Connection::system().await?;
    let rule = zbus::MatchRule::builder()
        .msg_type(zbus::message::Type::Signal)
        .sender("org.bluez")?
        .interface("org.freedesktop.DBus.Properties")?
        .member("PropertiesChanged")?
        .arg(0, "org.bluez.Device1")?
        .build();
    let changes = zbus::MessageStream::for_match_rule(rule, &conn, None).await?;
    Ok(changes.filter_map(|message| async move {
        let message = message.ok()?;
        let body = message.body();
        let (_, changed, _): (String, HashMap<String, Value>, Vec<String>) = body.deserialize().ok()?;
        changed.contains_key("Connected").then_some(())
    }))
}

pub async fn connect_device(device: &bluer::Device) -> Result<()> {
    tracing::info!("Connecting to device via BlueZ...");
    let _: () = device.connect().await.context("Failed to connect device")?;
    Ok(())
}

pub async fn disconnect_device(device: &bluer::Device) -> Result<()> {
    tracing::info!("Disconnecting device via BlueZ...");
    let _: () = device
        .disconnect()
        .await
        .context("Failed to disconnect device")?;
    Ok(())
}

pub async fn pair_device(device: &bluer::Device) -> Result<()> {
    tracing::info!("Pairing with device...");
    let _: () = device.pair().await.context("Failed to pair device")?;
    Ok(())
}

pub async fn trust_device(device: &bluer::Device) -> Result<()> {
    tracing::info!("Trusting device for auto-reconnect...");
    let _: () = device
        .set_trusted(true)
        .await
        .context("Failed to trust device")?;
    Ok(())
}

/// Expose the AirPods as plain "AirPods" with A2DP only. Dropping the headset
/// profiles removes the low-quality HFP mic (the daemon provides the hi-res
/// one) and leaves the audio server nothing to switch to when apps record.
pub async fn a2dp_only(device: &bluer::Device) -> Result<()> {
    const HFP_HF: Uuid = Uuid::from_u128(0x0000111e_0000_1000_8000_00805f9b34fb);
    const HSP_HS: Uuid = Uuid::from_u128(0x00001108_0000_1000_8000_00805f9b34fb);

    device.set_alias("AirPods".to_string()).await?;
    for uuid in [HFP_HF, HSP_HS] {
        if let Err(e) = device.disconnect_profile(&uuid).await {
            tracing::debug!("disconnect profile {}: {}", uuid, e);
        }
    }
    Ok(())
}

// Monitor device events
pub async fn monitor_device_events(
    adapter: &bluer::Adapter,
    mut on_device_added: impl FnMut(DeviceInfo) + Send + 'static,
    mut on_device_connected: impl FnMut(Address) + Send + 'static,
    mut on_device_disconnected: impl FnMut(Address) + Send + 'static,
) -> Result<()> {
    use futures::stream::StreamExt;

    let mut device_events = adapter.discover_devices().await?;

    while let Some(evt) = device_events.next().await {
        match evt {
            bluer::AdapterEvent::DeviceAdded(addr) => {
                let device = adapter.device(addr)?;

                if is_airpods_device(&device).await {
                    let name: Option<String> = device.name().await?;
                    let name = name.unwrap_or_else(|| "Unknown".to_string());
                    let connected: Result<bool, _> = device.is_connected().await;
                    let connected = connected.unwrap_or(false);
                    let paired: Result<bool, _> = device.is_paired().await;
                    let paired = paired.unwrap_or(false);

                    tracing::info!("AirPods found: {} ({})", name, addr);

                    on_device_added(DeviceInfo {
                        address: addr,
                        name,
                        connected,
                        paired,
                    });
                }
            }
            bluer::AdapterEvent::DeviceRemoved(addr) => {
                tracing::debug!("Device removed: {}", addr);
            }
            bluer::AdapterEvent::PropertyChanged(_) => {}
        }
    }

    Ok(())
}
