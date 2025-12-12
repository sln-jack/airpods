#pragma once

#include <dbus/dbus.h>
#include <types/device.hpp>
#include <functional>
#include <string>

namespace dbus_service {

// D-Bus service configuration
constexpr const char* SERVICE_NAME = "com.apple.Airpods";
constexpr const char* OBJECT_PATH = "/com/apple/Airpods";
constexpr const char* INTERFACE_NAME = "com.apple.Airpods";

// Callbacks for method invocations
struct Callbacks {
    std::function<void()> on_pair;
    std::function<void()> on_connect;
    std::function<void()> on_disconnect;
    std::function<void(airpods::NoiseControlMode)> on_set_noise_control;
};

// Current state exposed via D-Bus
struct State {
    bool connected = false;
    std::string noise_control_mode = "off";
    std::string device_name;
    std::string model;
    int32_t battery_left = -1;
    int32_t battery_right = -1;
    int32_t battery_case = -1;
    bool charging_left = false;
    bool charging_right = false;
    bool charging_case = false;
    bool left_in_ear = false;
    bool right_in_ear = false;
};

// Initialize D-Bus service, returns connection (caller owns)
// Sets up object path and method handlers
DBusConnection* init(Callbacks* callbacks, State* state);

// Request the service name on the bus
bool request_name(DBusConnection* conn);

// Emit PropertiesChanged signal for given properties
void emit_properties_changed(DBusConnection* conn, const State& state,
                              const char** property_names, int num_properties);

// Update state from DeviceState and emit signals
void update_from_device_state(DBusConnection* conn, State* state,
                               const airpods::DeviceState& device);

// Process pending D-Bus messages (call in event loop)
void process_pending(DBusConnection* conn);

// Get file descriptor for polling
int get_fd(DBusConnection* conn);

// Cleanup
void cleanup(DBusConnection* conn);

} // namespace dbus_service
