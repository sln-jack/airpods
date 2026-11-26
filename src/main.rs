use airpods::audio::{self, eld::{EldDecoder, TS_PER_FRAME}, mic::VirtualMic};
use airpods::bluez;
use airpods::dbus_service::{self, Callbacks};
use airpods::l2cap;
use airpods::protocol::{arbitration, commands, parse, packets};
use airpods::types::{DeviceState, NoiseControlMode};
use anyhow::Result;
use bluer::{Address, Session};
use clap::{Parser, Subcommand};
use futures::future::OptionFuture;
use futures::StreamExt;
use std::io::IsTerminal;
use std::os::fd::{BorrowedFd, RawFd};
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::unix::AsyncFd;
use tokio::signal::unix::{signal, SignalKind};
use tokio::sync::{broadcast, RwLock};
use tokio::time::sleep;
use tracing::{error, info, warn};

#[derive(Parser)]
#[command(name = "airpods")]
#[command(about = "AirPods daemon for Linux", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Run the AirPods daemon
    Daemon,
    /// Start pairing mode
    Pair,
    /// Connect the paired AirPods
    Up,
    /// Disconnect the AirPods
    Down,
    /// Show current status
    Status,
    /// Set noise control mode
    Noise { mode: String },
}

// Connection state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConnectionState {
    Disconnected,
    Connecting,
    Handshaking,
    WaitingFeatures,
    Connected,
}

// Daemon state
struct DaemonState {
    device_state: Arc<RwLock<DeviceState>>,
    connection_state: Arc<RwLock<ConnectionState>>,
    l2cap_connection: Arc<RwLock<Option<l2cap::Connection>>>,
    pairing_mode: Arc<RwLock<bool>>,
    mic: std::sync::Mutex<Option<Arc<VirtualMic>>>,
    a2dp: std::sync::OnceLock<bluez::a2dp::A2dp>,
    last_audio: std::sync::Mutex<Instant>,
    mic_reply: tokio::sync::Notify,
    shutdown_tx: broadcast::Sender<()>,
}

impl DaemonState {
    fn new() -> Self {
        let (shutdown_tx, _) = broadcast::channel(1);
        Self {
            device_state: Arc::new(RwLock::new(DeviceState::default())),
            connection_state: Arc::new(RwLock::new(ConnectionState::Disconnected)),
            l2cap_connection: Arc::new(RwLock::new(None)),
            pairing_mode: Arc::new(RwLock::new(false)),
            mic: std::sync::Mutex::new(None),
            a2dp: std::sync::OnceLock::new(),
            last_audio: std::sync::Mutex::new(Instant::now()),
            mic_reply: tokio::sync::Notify::new(),
            shutdown_tx,
        }
    }
}

async fn send_packet(connection: &mut l2cap::Connection, packet: &[u8]) -> Result<()> {
    connection.send(packet).await?;
    info!("-> sent {} bytes", packet.len());
    Ok(())
}

async fn handle_packet(state: &DaemonState, data: &[u8]) {
    let packet_type = parse::identify_packet(data);
    tracing::debug!("<- {:?} {}", packet_type, hex::encode(data));

    if packet_type == parse::PacketType::Arbitration {
        match arbitration::decode(data) {
            Ok(event) => info!("Arbitration {event}"),
            Err(reason) => warn!("Arbitration decode failed for opcode {:#04x} ({} bytes): {reason}", data[4], data.len()),
        }
        return;
    }

    let mut conn_state = state.connection_state.write().await;
    let mut device_state = state.device_state.write().await;

    match packet_type {
        parse::PacketType::HandshakeAck => {
            if *conn_state == ConnectionState::Handshaking {
                info!("Handshake acknowledged, sending features");
                if let Some(ref mut conn) = *state.l2cap_connection.write().await {
                    match send_packet(conn, &packets::connection::SET_FEATURES).await {
                        Ok(_) => info!("SET_FEATURES sent successfully"),
                        Err(e) => warn!("Failed to send SET_FEATURES: {}", e),
                    }
                }
                *conn_state = ConnectionState::WaitingFeatures;
            }
        }

        parse::PacketType::FeaturesAck => {
            if *conn_state == ConnectionState::WaitingFeatures {
                info!("Features acknowledged, requesting notifications");
                if let Some(ref mut conn) = *state.l2cap_connection.write().await {
                    let _ = send_packet(conn, &packets::connection::REQUEST_NOTIFICATIONS).await;
                    match send_packet(conn, &packets::connection::GET_TIPI_TABLE).await {
                        Ok(()) => info!("Arbitration requested device table"),
                        Err(e) => warn!("Arbitration table request failed: {e}"),
                    }
                }
                *conn_state = ConnectionState::Connected;
                device_state.connected = true;
                let mut mic = state.mic.lock().unwrap();
                if mic.is_none() {
                    *mic = VirtualMic::new().map(Arc::new);
                    match *mic {
                        Some(_) => info!("Hi-res mic ready"),
                        None => warn!("Failed to create hi-res mic source"),
                    }
                }
            }
        }

        parse::PacketType::Battery => {
            if let Some(battery) = parse::parse_battery(data) {
                device_state.battery = battery;
                info!(
                    "Battery: L={}% R={}% Case={}%",
                    battery.left.level, battery.right.level, battery.case_.level
                );
            }
        }

        parse::PacketType::EarDetection => {
            if let Some(ear) = parse::parse_ear_detection(data) {
                device_state.ear_detection = ear;
                info!(
                    "Ear: primary={} secondary={}",
                    if ear.primary_in_ear() { "in" } else { "out" },
                    if ear.secondary_in_ear() { "in" } else { "out" }
                );
            }
        }

        parse::PacketType::NoiseControlMode => {
            if let Some(mode) = parse::parse_noise_control_mode(data) {
                device_state.noise_control_mode = mode;
                info!("Noise control: {}", mode);
            }
        }

        parse::PacketType::Metadata => {
            if let Some(meta) = parse::parse_metadata(data) {
                device_state.device_name = meta.device_name.clone();
                device_state.model_number = meta.model_number.clone();
                device_state.model = airpods::types::Model::from_model_number(&meta.model_number);
                info!("Device: {} ({})", meta.device_name, meta.model_number);
            }
        }

        parse::PacketType::MagicKeys => {
            if let Some(keys) = parse::parse_magic_keys(data) {
                device_state.irk = keys.irk;
                device_state.enc_key = keys.enc_key;
                device_state.has_magic_keys = true;
                info!("Received magic pairing keys");
            }
        }

        _ => {}
    }
}

/// Set up playback and the control channel of connected AirPods. Returns
/// whether the daemon has their playback stream. Only `fresh`ly connected
/// AirPods are reconnected if that is what it takes to get the stream.
async fn connect_airpods(state: &DaemonState, session: &Session, mac_address: &str, fresh: bool) -> Result<bool> {
    info!("Connecting to {}...", mac_address);
    *state.connection_state.write().await = ConnectionState::Connecting;

    // Get adapter and device
    let adapter = bluez::get_default_adapter(session).await?;
    let address: Address = mac_address.parse()?;
    let device = adapter.device(address)?;

    let mut playback = false;
    if let Some(a2dp) = state.a2dp.get() {
        let path = format!("/org/bluez/{}/dev_{}", adapter.name(), mac_address.replace(':', "_"));
        let stream = if fresh { a2dp.select(&path).await } else { a2dp.configure(&path).await };
        match stream {
            Ok(()) => playback = true,
            Err(e) => warn!("AAC-ELD playback unavailable: {:#}", e),
        }
    }
    // Only once playback is set up: dropping profiles earlier cancels a
    // connection that is still in progress.
    if let Err(e) = bluez::a2dp_only(&device).await {
        warn!("Failed to set up A2DP-only audio: {}", e);
    }

    // The control channel can take a moment to accept connections.
    const MAX_RETRIES: usize = 5;
    const RETRY_DELAY: Duration = Duration::from_secs(2);
    let mut attempt = 1;
    let mut connection = loop {
        // Connecting the channel would bring back AirPods that just left.
        anyhow::ensure!(device.is_connected().await?, "the AirPods disconnected");
        match l2cap::connect(mac_address).await {
            Ok(connection) => break connection,
            Err(e) if attempt < MAX_RETRIES => warn!("L2CAP connection attempt {}/{} failed: {:#}", attempt, MAX_RETRIES, e),
            Err(e) => return Err(e),
        }
        attempt += 1;
        sleep(RETRY_DELAY).await;
    };

    // Update state
    state.device_state.write().await.mac_address = mac_address.to_string();
    *state.connection_state.write().await = ConnectionState::Handshaking;

    // Send handshake
    info!("Sending handshake...");
    send_packet(&mut connection, &packets::connection::HANDSHAKE).await?;

    // Store connection
    *state.l2cap_connection.write().await = Some(connection);

    Ok(playback)
}

async fn disconnect_airpods(state: &DaemonState) {
    info!("Disconnecting...");

    if let Some(conn) = state.l2cap_connection.write().await.take() {
        conn.close().await;
    }

    *state.connection_state.write().await = ConnectionState::Disconnected;
    state.device_state.write().await.connected = false;
    state.mic.lock().unwrap().take();
}

async fn recv_loop(state: &DaemonState, fd: RawFd) -> Result<()> {
    unsafe {
        let flags = libc::fcntl(fd, libc::F_GETFL);
        libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
    }
    let afd = AsyncFd::new(unsafe { BorrowedFd::borrow_raw(fd) })?;

    let mut eld = EldDecoder::new();
    if eld.is_none() {
        warn!("AAC-ELD decoder unavailable; hi-res mic disabled");
    }
    // Hi-res mic packets can exceed 1 KB; SEQPACKET truncates silently.
    let mut buf = vec![0u8; 4096];
    let mut pcm = Vec::new();
    let mut next_ts: Option<u32> = None;
    loop {
        let mut ready = afd.readable().await?;
        let n = match ready.try_io(|_| {
            let n = unsafe { libc::recv(fd, buf.as_mut_ptr().cast(), buf.len(), 0) };
            if n < 0 { Err(std::io::Error::last_os_error()) } else { Ok(n as usize) }
        }) {
            Ok(r) => r?,
            Err(_would_block) => continue,
        };
        if n == 0 {
            return Ok(());
        }
        let data = &buf[..n];
        if !audio::is_audio(data) {
            if audio::is_reply(data) {
                state.mic_reply.notify_one();
            }
            handle_packet(state, data).await;
            continue;
        }
        *state.last_audio.lock().unwrap() = Instant::now();
        let (Some(eld), Some(mic)) = (eld.as_mut(), state.mic.lock().unwrap().clone()) else {
            continue;
        };
        if !mic.streaming() {
            next_ts = None;
            continue;
        }
        pcm.clear();
        let mut first_ts = None;
        for (ts, frame) in audio::frames(data) {
            if let Some(expected) = next_ts {
                let lost = ts.wrapping_sub(expected) as i32 / TS_PER_FRAME as i32;
                for _ in 0..lost.clamp(0, 64) {
                    eld.conceal(&mut pcm);
                }
            }
            next_ts = Some(ts.wrapping_add(TS_PER_FRAME));
            first_ts.get_or_insert(ts);
            eld.decode(frame, &mut pcm);
        }
        if let Some(ts) = first_ts {
            mic.push(&pcm, ts);
        }
    }
}

/// Run the AirPods mic stream only while an app records from the virtual
/// source, restarting it if packets stop arriving.
async fn mic_monitor(state: Arc<DaemonState>) {
    const STALL: Duration = Duration::from_secs(2);
    let mut capturing = false;
    loop {
        // React to recording starting/stopping immediately; the timeout only
        // paces the stall check.
        let changed = state.mic.lock().unwrap().as_ref().map(|m| m.changed());
        match changed {
            Some(n) => drop(tokio::time::timeout(Duration::from_millis(250), n.notified()).await),
            None => sleep(Duration::from_millis(250)).await,
        }
        let mic = state.mic.lock().unwrap().clone();
        let want = mic.is_some_and(|m| m.streaming());
        let stalled = capturing && state.last_audio.lock().unwrap().elapsed() > STALL;
        if want == capturing && !stalled {
            continue;
        }
        if stalled {
            warn!("Hi-res mic stalled, restarting");
        }
        // The AirPods expect playback to be suspended while the mic is
        // switched, as an iPhone does; otherwise they can drop an ear.
        let a2dp = state.a2dp.get();
        if let Some(a2dp) = a2dp {
            a2dp.suspend().await;
        }
        let packet: &[u8] = if want { &audio::START } else { &audio::STOP };
        if let Some(ref mut conn) = *state.l2cap_connection.write().await {
            match send_packet(conn, packet).await {
                Ok(()) => drop(tokio::time::timeout(STALL, state.mic_reply.notified()).await),
                Err(e) => warn!("Failed to send mic {}: {}", if want { "START" } else { "STOP" }, e),
            }
        }
        if let Some(a2dp) = a2dp {
            a2dp.resume();
        }
        info!("Hi-res mic {}", if want { "started" } else { "stopped" });
        capturing = want;
        *state.last_audio.lock().unwrap() = Instant::now();
    }
}

async fn set_noise_control(state: &DaemonState, mode: NoiseControlMode) -> Result<()> {
    if *state.connection_state.read().await != ConnectionState::Connected {
        error!("Not connected");
        return Ok(());
    }

    let packet = commands::noise_control::for_mode(mode);
    if let Some(ref mut conn) = *state.l2cap_connection.write().await {
        send_packet(conn, &packet).await?;
    }

    Ok(())
}

async fn run_daemon() -> Result<()> {
    info!("AirPods daemon starting...");

    let state = Arc::new(DaemonState::new());

    // Initialize BlueZ session
    let session = Session::new().await?;
    let adapter = bluez::get_default_adapter(&session).await?;

    if let Ok(address) = adapter.address().await {
        info!("Arbitration local adapter {} address={address}", adapter.name());
    }

    match adapter.modalias().await {
        Ok(Some(id)) => info!("Arbitration local Device ID source={} vendor={:#06x} product={:#06x}",
                              id.source, id.vendor, id.product),
        Ok(None) => info!("Arbitration local Device ID unavailable"),
        Err(e) => warn!("Arbitration could not read local Device ID: {e}"),
    }

    match bluez::a2dp::A2dp::register(adapter.name()).await {
        Ok(a2dp) => drop(state.a2dp.set(a2dp)),
        Err(e) => warn!("AAC-ELD playback unavailable: {:#}", e),
    }

    // Set up D-Bus service callbacks
    let callbacks = {
        let state_pair = state.clone();
        let adapter_pair = adapter.clone();
        let adapter_connect = adapter.clone();
        let adapter_disconnect = adapter.clone();
        let state_noise = state.clone();

        Callbacks {
            on_pair: Some(Box::new(move || {
                let state = state_pair.clone();
                let adapter = adapter_pair.clone();
                tokio::spawn(async move {
                    info!("Starting discovery for pairing...");
                    *state.pairing_mode.write().await = true;
                    let _ = bluez::start_discovery(&adapter).await;

                    // Check for already-discovered AirPods
                    if let Ok(unpaired) = bluez::find_unpaired_airpods(&adapter).await {
                        for dev in unpaired {
                            info!("Found already-discovered AirPods: {} ({})", dev.name, dev.address);
                            let device = adapter.device(dev.address).unwrap();
                            if bluez::pair_device(&device).await.is_ok() {
                                info!("Pairing initiated");
                                let _ = bluez::trust_device(&device).await;
                                let _ = bluez::stop_discovery(&adapter).await;
                                *state.pairing_mode.write().await = false;
                                return;
                            }
                        }
                    }
                });
            })),

            on_connect: Some(Box::new(move || {
                let adapter = adapter_connect.clone();
                tokio::spawn(async move { connect_paired(&adapter).await.unwrap_or_else(|e| warn!("{:#}", e)) });
            })),

            on_disconnect: Some(Box::new(move || {
                let adapter = adapter_disconnect.clone();
                tokio::spawn(async move { disconnect_connected(&adapter).await.unwrap_or_else(|e| warn!("{:#}", e)) });
            })),

            on_set_noise_control: Some(Box::new(move |mode| {
                let state = state_noise.clone();
                tokio::spawn(async move {
                    let _ = set_noise_control(&state, mode).await;
                });
            })),
        }
    };

    // Start D-Bus service - connection must stay in scope for daemon lifetime
    let _dbus_conn = dbus_service::start_service(state.device_state.clone(), callbacks).await?;

    info!("Daemon ready. D-Bus service: {}", dbus_service::SERVICE_NAME);

    tokio::spawn(follow(state.clone(), session.clone(), adapter.clone()));
    tokio::spawn(mic_monitor(state.clone()));

    let mut terminate = signal(SignalKind::terminate())?;
    let mut interrupt = signal(SignalKind::interrupt())?;
    let mut shutdown_rx = state.shutdown_tx.subscribe();
    tokio::select! {
        _ = terminate.recv() => {}
        _ = interrupt.recv() => {}
        _ = shutdown_rx.recv() => {}
    }
    // BlueZ doesn't close the stream of an endpoint that just goes away, and
    // the AirPods then refuse a new one until they reconnect.
    info!("Shutting down");
    disconnect_connected(&adapter).await
}

/// Stay attached to the AirPods for as long as the daemon runs: set up audio
/// and the control channel whenever they connect, and again if either drops.
/// Connecting them is left to the AirPods and the user, so that the daemon
/// never takes them from another device.
async fn follow(state: Arc<DaemonState>, session: Session, adapter: bluer::Adapter) {
    const RETRY_DELAY: Duration = Duration::from_secs(2);
    let mut changes = match bluez::connection_changes().await {
        Ok(changes) => Box::pin(changes),
        Err(e) => return error!("Cannot watch for AirPods: {:#}", e),
    };
    let mut fresh = true;
    loop {
        let Ok(Some(airpods)) = bluez::find_connected_airpods(&adapter).await else {
            fresh = true;
            changes.next().await;
            continue;
        };
        info!("AirPods connected: {}", airpods.name);
        let attached = connect_airpods(&state, &session, &airpods.address.to_string(), fresh).await;
        fresh = false;
        if let Ok(playback) = attached {
            let fd = state.l2cap_connection.read().await.as_ref().map(|c| c.fd());
            let a2dp = state.a2dp.get().filter(|_| playback);
            tokio::select! {
                Some(Err(e)) = OptionFuture::from(fd.map(|fd| recv_loop(&state, fd))) => warn!("L2CAP error: {}", e),
                Some(()) = OptionFuture::from(a2dp.map(|a2dp| a2dp.lost())) => info!("Playback stream closed"),
                else => {}
            }
        }
        disconnect_airpods(&state).await;
        match attached {
            Ok(_) => sleep(RETRY_DELAY).await,
            // Try again when they next connect, not in a loop.
            Err(e) => {
                warn!("AirPods not set up: {:#}", e);
                changes.next().await;
            }
        }
    }
}

/// Ask BlueZ to connect the first paired AirPods in range.
async fn connect_paired(adapter: &bluer::Adapter) -> Result<()> {
    let mut connected = Err(anyhow::anyhow!("no paired AirPods"));
    for airpods in bluez::find_paired_airpods(adapter).await? {
        let device = adapter.device(airpods.address)?;
        connected = bluez::connect_device(&device).await;
        // BlueZ also fails the call when the daemon sets up the playback
        // stream before BlueZ's own attempt at it.
        if connected.is_ok() || device.is_connected().await.unwrap_or(false) {
            return Ok(());
        }
    }
    connected
}

async fn disconnect_connected(adapter: &bluer::Adapter) -> Result<()> {
    if let Some(airpods) = bluez::find_connected_airpods(adapter).await? {
        bluez::disconnect_device(&adapter.device(airpods.address)?).await?;
    }
    Ok(())
}

async fn default_adapter() -> Result<bluer::Adapter> {
    bluez::get_default_adapter(&Session::new().await?).await
}

async fn cmd_pair() -> Result<()> {
    let conn = zbus::Connection::session().await?;

    let proxy = zbus::Proxy::new(
        &conn,
        dbus_service::SERVICE_NAME,
        dbus_service::OBJECT_PATH,
        dbus_service::SERVICE_NAME,
    )
    .await?;

    proxy.call_method("Pair", &()).await?;

    println!("Searching for AirPods...");
    println!("Put AirPods in pairing mode: open the case lid, then press and hold");
    println!("the button on the back (or touch and hold the front status light on");
    println!("newer models) until the light flashes white.");
    println!();

    // Poll for connection with timeout (60 seconds)
    for i in 0..120 {
        sleep(Duration::from_millis(500)).await;

        let connected: bool = proxy
            .get_property("Connected")
            .await
            .unwrap_or(false);

        if connected {
            let name: String = proxy.get_property("DeviceName").await.unwrap_or_default();
            let model: String = proxy.get_property("Model").await.unwrap_or_default();

            println!("Paired and connected!");
            println!("  Device: {}", if name.is_empty() { "(unknown)" } else { &name });
            println!("  Model:  {}", if model.is_empty() { "(unknown)" } else { &model });
            return Ok(());
        }

        if (i % 4) == 0 {
            print!(".");
            use std::io::Write;
            std::io::stdout().flush().unwrap();
        }
    }

    println!("\nTimeout waiting for AirPods to pair");
    Ok(())
}

async fn cmd_status() -> Result<()> {
    let conn = zbus::Connection::session().await?;

    let proxy = zbus::Proxy::new(
        &conn,
        dbus_service::SERVICE_NAME,
        dbus_service::OBJECT_PATH,
        dbus_service::SERVICE_NAME,
    )
    .await?;

    let connected: bool = proxy.get_property("Connected").await?;
    let name: String = proxy.get_property("DeviceName").await?;
    let model: String = proxy.get_property("Model").await?;
    let noise_mode: String = proxy.get_property("NoiseControlMode").await?;
    let battery_left: i32 = proxy.get_property("BatteryLeft").await?;
    let battery_right: i32 = proxy.get_property("BatteryRight").await?;
    let battery_case: i32 = proxy.get_property("BatteryCase").await?;
    let charging_left: bool = proxy.get_property("ChargingLeft").await?;
    let charging_right: bool = proxy.get_property("ChargingRight").await?;
    let charging_case: bool = proxy.get_property("ChargingCase").await?;
    let left_in_ear: bool = proxy.get_property("LeftInEar").await?;
    let right_in_ear: bool = proxy.get_property("RightInEar").await?;

    println!("Connected: {}", connected);
    println!("DeviceName: {}", name);
    println!("Model: {}", model);
    println!("NoiseControlMode: {}", noise_mode);
    println!("BatteryLeft: {}{}", battery_left, if charging_left { " (charging)" } else { "" });
    println!("BatteryRight: {}{}", battery_right, if charging_right { " (charging)" } else { "" });
    println!("BatteryCase: {}{}", battery_case, if charging_case { " (charging)" } else { "" });
    println!("LeftInEar: {}", left_in_ear);
    println!("RightInEar: {}", right_in_ear);

    Ok(())
}

async fn cmd_set_noise_control(mode_str: &str) -> Result<()> {
    NoiseControlMode::from_str(mode_str)
        .map_err(|_| anyhow::anyhow!("Invalid mode: {}. Valid modes: off, anc, transparency, adaptive", mode_str))?;

    let conn = zbus::Connection::session().await?;

    let proxy = zbus::Proxy::new(
        &conn,
        dbus_service::SERVICE_NAME,
        dbus_service::OBJECT_PATH,
        dbus_service::SERVICE_NAME,
    )
    .await?;

    proxy.call_method("SetNoiseControl", &(mode_str,)).await?;

    println!("Noise control set to: {}", mode_str);
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_ansi(std::io::stdout().is_terminal())
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Daemon => run_daemon().await,
        Commands::Pair => cmd_pair().await,
        Commands::Up => connect_paired(&default_adapter().await?).await,
        Commands::Down => disconnect_connected(&default_adapter().await?).await,
        Commands::Status => cmd_status().await,
        Commands::Noise { mode } => cmd_set_noise_control(&mode).await,
    }
}
