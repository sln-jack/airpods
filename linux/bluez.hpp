#pragma once

#include <dbus/dbus.h>
#include <functional>
#include <optional>
#include <string>
#include <vector>

namespace bluez {

// AirPods service UUID
constexpr const char* AIRPODS_UUID = "74ec2172-0bad-4d01-8f77-997b2be0722a";

// Device info
struct DeviceInfo {
    std::string path;       // D-Bus object path
    std::string address;    // MAC address
    std::string name;
    bool connected;
    bool paired;
};

// Callbacks for BlueZ events
struct Callbacks {
    std::function<void(const DeviceInfo&)> on_airpods_found;
    std::function<void(const std::string& address)> on_device_connected;
    std::function<void(const std::string& address)> on_device_disconnected;
};

// Check if UUIDs contain AirPods UUID
bool is_airpods(DBusMessageIter* uuids_iter);

// Check if device name looks like AirPods
bool is_airpods_name(const std::string& name);

// Get adapter path (usually /org/bluez/hci0)
std::optional<std::string> get_adapter_path(DBusConnection* conn);

// Find all paired AirPods
std::vector<DeviceInfo> find_paired_airpods(DBusConnection* conn);

// Find first connected AirPods
std::optional<DeviceInfo> find_connected_airpods(DBusConnection* conn);

// Find unpaired AirPods (discovered but not yet paired)
std::vector<DeviceInfo> find_unpaired_airpods(DBusConnection* conn);

// Start BLE discovery
bool start_discovery(DBusConnection* conn);

// Stop discovery
void stop_discovery(DBusConnection* conn);

// Connect device via BlueZ
bool connect_device(DBusConnection* conn, const std::string& device_path);

// Disconnect device
bool disconnect_device(DBusConnection* conn, const std::string& device_path);

// Pair device
bool pair_device(DBusConnection* conn, const std::string& device_path);

// Trust device (for auto-reconnect)
bool trust_device(DBusConnection* conn, const std::string& device_path);

// Activate A2DP profile for high-quality audio (instead of HSP/HFP)
bool activate_a2dp(DBusConnection* conn, const std::string& mac_address);

// Get BlueZ device path from MAC address
std::string get_device_path(const std::string& mac_address);

// Set up signal matching for BlueZ events (InterfacesAdded, PropertiesChanged)
void setup_signal_handlers(DBusConnection* conn, const Callbacks* callbacks);

// Process a D-Bus message that might be a BlueZ signal
// Returns true if it was handled
bool handle_signal(DBusConnection* conn, DBusMessage* msg, const Callbacks* callbacks);

} // namespace bluez
