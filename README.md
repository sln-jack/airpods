# airpods

Screw you apple, I'll do it myself.

A complete Rust rewrite of the AirPods daemon for Linux, featuring:
- Full protocol support for AirPods (battery, ear detection, noise control)
- BlueZ integration via D-Bus
- L2CAP socket communication
- Session D-Bus service for client control
- PipeWire integration for audio management

## Requirements

### System Dependencies

Install the following packages for your distribution:

**Arch/Manjaro:**
```bash
sudo pacman -S dbus bluez pipewire
```

**Ubuntu/Debian:**
```bash
sudo apt install libdbus-1-dev pkg-config bluez pipewire
```

**Fedora/RHEL:**
```bash
sudo dnf install dbus-devel pkgconf-pkg-config bluez pipewire
```

### Rust Toolchain

Requires Rust 1.70+ with edition 2021:
```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

## Building

```bash
cargo build --release
```

The binary will be at `target/release/airpods`.

## Installation

```bash
# Install binary
sudo cp target/release/airpods /usr/local/bin/

# Install systemd service (optional)
mkdir -p ~/.config/systemd/user/
cp airpods.service ~/.config/systemd/user/
systemctl --user enable --now airpods
```

### WirePlumber

The daemon provides the AirPods' sink and source itself, so WirePlumber's
Bluetooth monitor has to be off. Left on, it adds a second, HFP-only "AirPods"
sink and source, and takes the playback stream on connect, which the daemon
can only win back by reconnecting the AirPods.

WirePlumber 0.4, in `~/.config/wireplumber/bluetooth.lua.d/51-no-bluez.lua`:

```lua
bluez_monitor.enabled = false
```

WirePlumber 0.5+, in `~/.config/wireplumber/wireplumber.conf.d/51-no-bluez.conf`:

```
wireplumber.profiles = { main = { monitor.bluez = disabled } }
```

Then `systemctl --user restart wireplumber`. Other Bluetooth audio devices
stop appearing in PipeWire.

## Usage

### Run the daemon

```bash
airpods daemon
```

The daemon will:
1. Connect to BlueZ via system D-Bus
2. Expose a session D-Bus service at `com.apple.Airpods`
3. Set up audio and the control channel whenever paired AirPods connect
4. Manage L2CAP communication and state

It never connects the AirPods on its own, so it won't take them from a phone.

### Connect and disconnect

```bash
airpods up      # Connect the paired AirPods
airpods down    # Disconnect them
```

### Capture an automatic switching diagnostic

Disconnect the AirPods from the Mac and play audio on the iPhone. From the Linux checkout run:

```bash
cargo build --release
./scripts/test-arbitration.sh
```

The helper runs the local build, calls `airpods up` once, and saves the device table, ownership reports, and relays in the log path it prints. If phone audio stops, tap Play on the phone once during the 30-second observation window. The helper temporarily stops an active user `airpods.service` and restores it on exit.

### Pair AirPods

Put your AirPods in pairing mode (case lid open, hold button until light flashes white), then:

```bash
airpods pair
```

### Check status

```bash
airpods status
```

Shows:
- Connection state
- Device name and model
- Battery levels (left, right, case)
- Charging status
- Ear detection state
- Noise control mode

### Control noise cancellation

```bash
airpods noise off         # Disable
airpods noise anc         # Active Noise Cancellation
airpods noise transparency    # Transparency mode
airpods noise adaptive    # Adaptive (AirPods Pro 2)
```

## D-Bus Interface

The daemon exposes `com.apple.Airpods` on the session bus at `/com/apple/Airpods`.

### Methods

- `Pair()` - Start pairing mode
- `Connect()` - Connect to paired AirPods
- `Disconnect()` - Disconnect
- `SetNoiseControl(mode: String)` - Set noise control mode

### Properties (read-only unless noted)

- `Connected: bool`
- `DeviceName: String`
- `Model: String`
- `NoiseControlMode: String`
- `BatteryLeft: int`
- `BatteryRight: int`
- `BatteryCase: int`
- `ChargingLeft: bool`
- `ChargingRight: bool`
- `ChargingCase: bool`
- `LeftInEar: bool`
- `RightInEar: bool`

### Example: Monitor battery with D-Bus

```bash
dbus-monitor --session "type='signal',interface='com.apple.Airpods'"
```

## Architecture

- **Rust + Tokio** - Async runtime
- **zbus 4** - D-Bus integration with tokio support
- **bluer** - BlueZ Bluetooth stack integration
- **L2CAP sockets** - Direct AirPods protocol communication
- **PipeWire** - Audio routing management

## Protocol

The AirPods use a proprietary protocol over L2CAP PSM (discovered via SDP):
- Handshake with feature negotiation
- Binary packets for battery, ear detection, noise control
- Real-time state updates

This implementation reverse-engineers and fully implements the protocol.

## License

MIT

## Credits

Inspired by the original C++ implementation. Completely rewritten in Rust for improved safety, concurrency, and maintainability.
