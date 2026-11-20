//! A2DP playback over Apple's AAC-ELD vendor codec, which the audio server
//! doesn't speak. The daemon registers its own media endpoint with BlueZ and
//! gets the AirPods' stream configured on it; audio then flows through
//! [`Sink`].

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result};
use futures::StreamExt;
use tokio::sync::watch;
use tokio::task::JoinHandle;
use zbus::zvariant::{ObjectPath, OwnedFd, OwnedObjectPath, OwnedValue, Value};
use zbus::Connection;

use crate::audio::sink::{self, Sink};

const ENDPOINT: &str = "/airpods/a2dp";
const A2DP_SOURCE: &str = "0000110a-0000-1000-8000-00805f9b34fb";
const CODEC_VENDOR: u8 = 0xff;
/// Apple (0x004C) codec 0x8001: AAC-ELD, 48 kHz, mono or stereo, VBR, 256 kbit/s.
const CAPABILITIES: [u8; 14] = [0x4c, 0, 0, 0, 0x01, 0x80, 0x00, 0x80, 0x00, 0x8c, 0x00, 0x83, 0xe8, 0x00];
/// The same, narrowed to stereo.
const CONFIGURATION: [u8; 14] = [0x4c, 0, 0, 0, 0x01, 0x80, 0x00, 0x80, 0x00, 0x84, 0x00, 0x83, 0xe8, 0x00];
const VENDOR_CODEC: std::ops::Range<usize> = 0..6;
/// How long to wait for BlueZ to finish setting up a connected device.
const SETUP: Duration = Duration::from_secs(5);
const RETRY: Duration = Duration::from_millis(200);
/// How long the AirPods may take to reconnect, a BlueZ restart included.
const RECONNECT: Duration = Duration::from_secs(15);

#[zbus::proxy(interface = "org.bluez.MediaTransport1", default_service = "org.bluez")]
trait MediaTransport {
    /// Returns the stream socket with its read and write MTUs.
    fn acquire(&self) -> zbus::Result<(OwnedFd, u16, u16)>;
    fn release(&self) -> zbus::Result<()>;
    #[zbus(property)]
    fn state(&self) -> zbus::Result<String>;
    #[zbus(property)]
    fn volume(&self) -> zbus::Result<u16>;
    #[zbus(property)]
    fn set_volume(&self, volume: u16) -> zbus::Result<()>;
}

#[derive(Default)]
struct Shared {
    playing: Mutex<Option<JoinHandle<()>>>,
    /// Whether BlueZ has a stream configured on the endpoint.
    configured: watch::Sender<bool>,
    /// Set by whoever needs the stream suspended.
    suspend: watch::Sender<bool>,
    /// Whether the transport is acquired, or about to be.
    held: watch::Sender<bool>,
}

impl Shared {
    fn start(self: &Arc<Self>, conn: Connection, transport: OwnedObjectPath) {
        let shared = self.clone();
        let task = tokio::spawn(async move {
            if let Err(e) = play(conn, transport, &shared).await {
                tracing::warn!("AirPods playback failed: {:#}", e);
            }
            shared.held.send_replace(false);
        });
        if let Some(old) = self.playing.lock().unwrap().replace(task) {
            old.abort();
        }
        self.configured.send_replace(true);
    }

    fn stop(&self) {
        if let Some(task) = self.playing.lock().unwrap().take() {
            task.abort();
            self.held.send_replace(false);
            self.configured.send_replace(false);
            tracing::info!("AirPods playback stopped");
        }
    }
}

struct Endpoint {
    conn: Connection,
    shared: Arc<Shared>,
}

#[zbus::interface(name = "org.bluez.MediaEndpoint1")]
impl Endpoint {
    async fn set_configuration(&self, transport: OwnedObjectPath, _properties: HashMap<String, OwnedValue>) {
        self.shared.start(self.conn.clone(), transport);
    }

    async fn select_configuration(&self, _capabilities: Vec<u8>) -> Vec<u8> {
        CONFIGURATION.to_vec()
    }

    async fn clear_configuration(&self, _transport: OwnedObjectPath) {
        self.shared.stop();
    }

    async fn release(&self) {
        self.shared.stop();
    }
}

/// Run the sink on a configured transport until the task is aborted. Like
/// an iPhone, the stream only runs while something is playing: the AirPods
/// stop playing a stream that pauses, until it is suspended and started again.
async fn play(conn: Connection, path: OwnedObjectPath, shared: &Shared) -> Result<()> {
    let transport = MediaTransportProxy::builder(&conn).path(path)?.build().await?;
    let (sink, mut requested) = Sink::new().context("creating the sink")?;
    tracing::info!("AirPods playback ready (AAC-ELD)");

    let wake = sink.changed();
    let mut suspend = shared.suspend.subscribe();
    let mut state = transport.receive_state_changed().await;
    let mut reported = transport.receive_volume_changed().await;
    if let Ok(volume) = transport.volume().await {
        sink.set_volume(volume);
    }
    // Acquired; `active` once BlueZ has confirmed it, so that an "idle" from
    // before the acquisition isn't mistaken for a suspension.
    let (mut acquired, mut active) = (false, false);
    let mut cycle = tokio::time::interval(sink::CYCLE);
    cycle.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        // Announce the acquisition before checking for a suspension request,
        // so that `A2dp::suspend` can't miss one in progress.
        if sink.streaming() {
            shared.held.send_replace(true);
        }
        let want = sink.streaming() && !*suspend.borrow_and_update();
        if want && !acquired {
            match transport.acquire().await {
                Ok((fd, _, mtu)) => {
                    acquired = sink.set_transport(fd.into(), mtu as usize);
                    tracing::debug!("transport acquired");
                }
                Err(e) => {
                    tracing::warn!("acquiring the transport: {}", e);
                    tokio::time::sleep(RETRY).await;
                    continue;
                }
            }
        } else if !want {
            sink.clear_transport();
            if acquired {
                tracing::debug!("releasing the transport");
                if let Err(e) = transport.release().await {
                    tracing::debug!("releasing the transport: {}", e);
                }
                (acquired, active) = (false, false);
            }
        }
        shared.held.send_replace(acquired);

        tokio::select! {
            _ = cycle.tick(), if acquired => sink.cycle(),
            _ = wake.notified() => {}
            _ = suspend.changed() => {}
            Some(change) = state.next() => match change.get().await.as_deref() {
                Ok("active") => active = acquired,
                Ok("idle") if active => {
                    sink.clear_transport();
                    (acquired, active) = (false, false);
                }
                _ => {}
            },
            Ok(()) = requested.changed() => {
                let volume = *requested.borrow_and_update();
                if let Err(e) = transport.set_volume(volume).await {
                    tracing::debug!("set volume: {}", e);
                }
            }
            Some(change) = reported.next() => {
                if let Ok(volume) = change.get().await {
                    sink.set_volume(volume);
                }
            }
        }
    }
}

/// Stop or start the audio server's session manager, which registers the
/// Bluetooth endpoints that compete with ours.
async fn session_manager(verb: &str) {
    let status = tokio::process::Command::new("systemctl").args(["--user", verb, "wireplumber.service"]).status().await;
    if !status.is_ok_and(|status| status.success()) {
        tracing::warn!("systemctl --user {} wireplumber.service failed", verb);
    }
}

async fn register_endpoint(conn: &Connection, adapter: &str) -> Result<()> {
    let properties: HashMap<&str, Value> = HashMap::from([
        ("UUID", A2DP_SOURCE.into()),
        ("Codec", CODEC_VENDOR.into()),
        ("Capabilities", CAPABILITIES.to_vec().into()),
    ]);
    conn.call_method(
        Some("org.bluez"),
        format!("/org/bluez/{adapter}"),
        Some("org.bluez.Media1"),
        "RegisterEndpoint",
        &(ObjectPath::try_from(ENDPOINT)?, properties),
    )
    .await
    .context("registering the A2DP endpoint")?;
    Ok(())
}

pub struct A2dp {
    conn: Connection,
    shared: Arc<Shared>,
}

impl A2dp {
    /// Register the AAC-ELD endpoint on `adapter` (e.g. "hci0"), and again
    /// whenever BlueZ restarts.
    pub async fn register(adapter: &str) -> Result<Self> {
        let conn = Connection::system().await?;
        let shared = Arc::<Shared>::default();
        conn.object_server()
            .at(ENDPOINT, Endpoint { conn: conn.clone(), shared: shared.clone() })
            .await?;
        register_endpoint(&conn, adapter).await?;

        let mut owners = zbus::fdo::DBusProxy::new(&conn)
            .await?
            .receive_name_owner_changed_with_args(&[(0, "org.bluez")])
            .await?;
        let (bus, state, adapter) = (conn.clone(), shared.clone(), adapter.to_string());
        tokio::spawn(async move {
            while let Some(change) = owners.next().await {
                state.stop();
                if !change.args().is_ok_and(|args| args.new_owner().is_some()) {
                    continue;
                }
                // The adapter takes a moment to appear.
                let registered = tokio::time::timeout(SETUP, async {
                    while register_endpoint(&bus, &adapter).await.is_err() {
                        tokio::time::sleep(RETRY).await;
                    }
                });
                if registered.await.is_err() {
                    tracing::warn!("could not register the A2DP endpoint with the restarted BlueZ");
                }
            }
        });
        Ok(A2dp { conn, shared })
    }

    /// Suspend the stream, returning once it is, and keep it suspended until
    /// [`resume`](Self::resume).
    pub async fn suspend(&self) {
        self.shared.suspend.send_replace(true);
        let _ = self.shared.held.subscribe().wait_for(|held| !held).await;
    }

    pub fn resume(&self) {
        self.shared.suspend.send_replace(false);
    }

    /// Get the stream of the connected device at object path `device` onto
    /// the AAC-ELD endpoint, unless BlueZ has put it there already.
    pub async fn select(&self, device: &str) -> Result<()> {
        let Err(e) = self.configure(device).await else {
            return Ok(());
        };
        // Another stream is in the way, and BlueZ only lets its owner replace
        // it: the audio server's endpoint was given the stream, or the
        // AirPods still have that of a daemon that didn't shut down.
        // Reconnecting them closes it. (BlueZ 5.83 crashes on the disconnect
        // if the stream's owner is gone, and is back within seconds.)
        let connected = self.conn.call_method(
            Some("org.bluez"),
            device,
            Some("org.freedesktop.DBus.Properties"),
            "Get",
            &("org.bluez.Device1", "Connected"),
        );
        let connected: OwnedValue = connected.await?.body().deserialize()?;
        anyhow::ensure!(bool::try_from(connected)?, "the AirPods disconnected");
        tracing::info!("Reconnecting the AirPods ({:#})", e);
        let _ = self.device(device, "Disconnect").await;
        // BlueZ would pick the audio server's endpoint again, as the first
        // registered or the last used, so ours has to be the only one while
        // they connect.
        session_manager("stop").await;
        let ours = self.reconnect(device).await;
        session_manager("start").await;
        ours
    }

    async fn reconnect(&self, device: &str) -> Result<()> {
        let connect = async {
            while let Err(e) = self.device(device, "Connect").await {
                tracing::debug!("Connect: {}", e);
                tokio::time::sleep(RETRY).await;
            }
        };
        tokio::time::timeout(RECONNECT, connect).await.context("reconnecting the AirPods")?;
        let mut configured = self.shared.configured.subscribe();
        if tokio::time::timeout(SETUP, configured.wait_for(|c| *c)).await.is_err() {
            self.configure(device).await?;
        }
        Ok(())
    }

    async fn device(&self, device: &str, method: &str) -> zbus::Result<()> {
        self.conn.call_method(Some("org.bluez"), device, Some("org.bluez.Device1"), method, &()).await?;
        Ok(())
    }

    /// Resolves when BlueZ takes the stream away from the endpoint.
    pub async fn lost(&self) {
        let _ = self.shared.configured.subscribe().wait_for(|c| !*c).await;
    }

    async fn objects(&self) -> Result<zbus::fdo::ObjectManagerProxy<'static>> {
        Ok(zbus::fdo::ObjectManagerProxy::builder(&self.conn).destination("org.bluez")?.path("/")?.build().await?)
    }

    /// Ask BlueZ to configure the device's AAC-ELD endpoint with ours.
    pub async fn configure(&self, device: &str) -> Result<()> {
        let manager = self.objects().await?;
        // The device's endpoints appear as BlueZ discovers them, which can
        // be after it reports the device connected.
        let mut added = manager.receive_interfaces_added().await?;
        let remote = loop {
            if *self.shared.configured.borrow() {
                return Ok(());
            }
            let objects = manager.get_managed_objects().await?;
            let remote = objects.into_iter().find(|(path, interfaces)| {
                path.starts_with(device)
                    && interfaces
                        .iter()
                        .filter(|(name, _)| name.as_str() == "org.bluez.MediaEndpoint1")
                        .filter_map(|(_, properties)| properties.get("Capabilities"))
                        .filter_map(|caps| Vec::<u8>::try_from(caps.try_clone().ok()?).ok())
                        .any(|caps| caps.get(VENDOR_CODEC) == Some(&CAPABILITIES[VENDOR_CODEC]))
            });
            if let Some((path, _)) = remote {
                break path;
            }
            tokio::time::timeout(SETUP, added.next()).await.ok().context("device does not offer AAC-ELD")?;
        };

        let properties: HashMap<&str, Value> = HashMap::from([("Capabilities", CONFIGURATION.to_vec().into())]);
        self.conn
            .call_method(
                Some("org.bluez"),
                remote,
                Some("org.bluez.MediaEndpoint1"),
                "SetConfiguration",
                &(ObjectPath::try_from(ENDPOINT)?, properties),
            )
            .await
            .context("configuring the AAC-ELD stream")?;
        Ok(())
    }
}
