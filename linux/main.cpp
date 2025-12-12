#include "bluez.hpp"
#include "dbus.hpp"
#include "l2cap.hpp"
#include "pipewire.hpp"

#include <protocol/commands.hpp>
#include <protocol/packets.hpp>
#include <protocol/parse.hpp>
#include <types/device.hpp>

#include <poll.h>
#include <signal.h>
#include <unistd.h>

#include <atomic>
#include <cstring>
#include <iostream>

// Global state (for daemon mode)
static std::atomic<bool> g_running{true};
static airpods::DeviceState g_device_state;
static l2cap::Connection g_connection;
static DBusConnection* g_session_dbus = nullptr;
static DBusConnection* g_system_dbus = nullptr;
static dbus_service::State g_dbus_state;
static dbus_service::Callbacks g_dbus_callbacks;
static bluez::Callbacks g_bluez_callbacks;
static bool g_pairing_mode = false;

// Connection state machine
enum class ConnectionState {
    Disconnected,
    Connecting,
    Handshaking,
    WaitingFeatures,
    Connected,
};

static ConnectionState g_conn_state = ConnectionState::Disconnected;

// Signal handler
static void signal_handler(int signum) {
    std::cout << "\nReceived signal " << signum << ", shutting down..." << std::endl;
    g_running = false;
}

// Send packet helper
static bool send_packet(const std::vector<uint8_t>& packet) {
    if (!g_connection.is_open()) return false;
    bool ok = l2cap::send(g_connection, packet);
    if (ok) {
        std::cout << "-> sent " << packet.size() << " bytes" << std::endl;
    }
    return ok;
}

// Forward declarations
static void set_noise_control(airpods::NoiseControlMode mode);
static bool connect_airpods(const std::string& mac_address);
static void disconnect_airpods();

// Handle received packet
static void handle_packet(const std::vector<uint8_t>& data) {
    using namespace airpods;

    auto type = parse::identify_packet(data);
    std::cout << "<- recv " << data.size() << " bytes, type=" << static_cast<int>(type) << std::endl;

    switch (type) {
        case parse::PacketType::HandshakeAck:
            if (g_conn_state == ConnectionState::Handshaking) {
                std::cout << "Handshake acknowledged, sending features" << std::endl;
                send_packet({packets::connection::SET_FEATURES.begin(),
                            packets::connection::SET_FEATURES.end()});
                g_conn_state = ConnectionState::WaitingFeatures;
            }
            break;

        case parse::PacketType::FeaturesAck:
            if (g_conn_state == ConnectionState::WaitingFeatures) {
                std::cout << "Features acknowledged, requesting notifications" << std::endl;
                send_packet({packets::connection::REQUEST_NOTIFICATIONS.begin(),
                            packets::connection::REQUEST_NOTIFICATIONS.end()});
                g_conn_state = ConnectionState::Connected;
                g_device_state.connected = true;
                dbus_service::update_from_device_state(g_session_dbus, &g_dbus_state, g_device_state);
            }
            break;

        case parse::PacketType::Battery:
            if (auto battery = parse::parse_battery(data)) {
                g_device_state.battery = *battery;
                std::cout << "Battery: L=" << static_cast<int>(battery->left.level)
                          << "% R=" << static_cast<int>(battery->right.level)
                          << "% Case=" << static_cast<int>(battery->case_.level) << "%" << std::endl;
                dbus_service::update_from_device_state(g_session_dbus, &g_dbus_state, g_device_state);
            }
            break;

        case parse::PacketType::EarDetection:
            if (auto ear = parse::parse_ear_detection(data)) {
                g_device_state.ear_detection = *ear;
                std::cout << "Ear: primary=" << (ear->primary_in_ear() ? "in" : "out")
                          << " secondary=" << (ear->secondary_in_ear() ? "in" : "out") << std::endl;
                dbus_service::update_from_device_state(g_session_dbus, &g_dbus_state, g_device_state);
            }
            break;

        case parse::PacketType::NoiseControlMode:
            if (auto mode = parse::parse_noise_control_mode(data)) {
                g_device_state.noise_control_mode = *mode;
                std::cout << "Noise control: " << to_string(*mode) << std::endl;
                dbus_service::update_from_device_state(g_session_dbus, &g_dbus_state, g_device_state);
            }
            break;

        case parse::PacketType::Metadata:
            if (auto meta = parse::parse_metadata(data)) {
                g_device_state.device_name = meta->device_name;
                g_device_state.model_number = meta->model_number;
                g_device_state.model = model_from_model_number(meta->model_number);
                std::cout << "Device: " << meta->device_name
                          << " (" << meta->model_number << ")" << std::endl;
                dbus_service::update_from_device_state(g_session_dbus, &g_dbus_state, g_device_state);
            }
            break;

        case parse::PacketType::MagicKeys:
            if (auto keys = parse::parse_magic_keys(data)) {
                g_device_state.irk = keys->irk;
                g_device_state.enc_key = keys->enc_key;
                g_device_state.has_magic_keys = true;
                std::cout << "Received magic pairing keys" << std::endl;
            }
            break;

        default:
            break;
    }
}

// Connect to AirPods via L2CAP
static bool connect_airpods(const std::string& mac_address) {
    if (g_connection.is_open()) {
        std::cout << "Already connected" << std::endl;
        return true;
    }

    std::cout << "Connecting to " << mac_address << "..." << std::endl;
    g_conn_state = ConnectionState::Connecting;

    // Ensure BlueZ connection first and activate A2DP profile
    bluez::activate_a2dp(g_system_dbus, mac_address);

    // Disable suspend timeout to prevent audio delay after idle
    // Need a small delay for PipeWire to register the node
    usleep(500000);  // 500ms
    pipewire::disable_suspend_timeout(mac_address);

    // Connect L2CAP with retries (SDP service may not be ready immediately after pairing)
    constexpr int max_retries = 5;
    constexpr int retry_delay_ms = 2000;  // 2 seconds between retries

    for (int attempt = 1; attempt <= max_retries; ++attempt) {
        g_connection = l2cap::connect(mac_address);
        if (g_connection.is_open()) {
            break;
        }

        if (attempt < max_retries) {
            std::cout << "L2CAP connection attempt " << attempt << "/" << max_retries
                      << " failed, retrying in " << (retry_delay_ms / 1000) << "s..." << std::endl;
            usleep(retry_delay_ms * 1000);
        }
    }

    if (!g_connection.is_open()) {
        std::cerr << "L2CAP connection failed after " << max_retries << " attempts" << std::endl;
        g_conn_state = ConnectionState::Disconnected;
        return false;
    }

    g_device_state.mac_address = mac_address;
    g_conn_state = ConnectionState::Handshaking;

    // Send handshake
    std::cout << "Sending handshake..." << std::endl;
    send_packet({airpods::packets::connection::HANDSHAKE.begin(),
                airpods::packets::connection::HANDSHAKE.end()});

    return true;
}

// Disconnect
static void disconnect_airpods() {
    if (g_connection.is_open()) {
        g_connection.close();
    }
    g_conn_state = ConnectionState::Disconnected;
    g_device_state.connected = false;
    if (g_session_dbus) {
        dbus_service::update_from_device_state(g_session_dbus, &g_dbus_state, g_device_state);
    }
    std::cout << "Disconnected" << std::endl;
}

// Set noise control mode
static void set_noise_control(airpods::NoiseControlMode mode) {
    if (!g_connection.is_open() || g_conn_state != ConnectionState::Connected) {
        std::cerr << "Not connected" << std::endl;
        return;
    }

    auto packet = airpods::commands::noise_control::for_mode(mode);
    send_packet(packet);
}

// Process BlueZ signals from system bus
static DBusHandlerResult bluez_filter(DBusConnection* conn, DBusMessage* msg, void* data) {
    (void)conn;
    auto* callbacks = static_cast<bluez::Callbacks*>(data);

    if (dbus_message_get_type(msg) == DBUS_MESSAGE_TYPE_SIGNAL) {
        if (bluez::handle_signal(g_system_dbus, msg, callbacks)) {
            return DBUS_HANDLER_RESULT_HANDLED;
        }
    }
    return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

// Main event loop
static void run_event_loop() {
    while (g_running) {
        // Set up poll fds
        std::vector<pollfd> fds;

        // Session D-Bus fd
        int session_fd = dbus_service::get_fd(g_session_dbus);
        if (session_fd >= 0) {
            pollfd pfd = {};
            pfd.fd = session_fd;
            pfd.events = POLLIN;
            fds.push_back(pfd);
        }

        // System D-Bus fd
        int system_fd = -1;
        if (dbus_connection_get_unix_fd(g_system_dbus, &system_fd) && system_fd >= 0) {
            pollfd pfd = {};
            pfd.fd = system_fd;
            pfd.events = POLLIN;
            fds.push_back(pfd);
        }

        // L2CAP fd if connected
        int l2cap_fd_idx = -1;
        if (g_connection.is_open()) {
            pollfd pfd = {};
            pfd.fd = l2cap::get_fd(g_connection);
            pfd.events = POLLIN;
            l2cap_fd_idx = static_cast<int>(fds.size());
            fds.push_back(pfd);
        }

        // Poll with 100ms timeout
        int ret = poll(fds.data(), fds.size(), 100);
        if (ret < 0) {
            if (errno == EINTR) continue;
            std::cerr << "poll error: " << strerror(errno) << std::endl;
            break;
        }

        // Process session D-Bus
        if (!fds.empty() && (fds[0].revents & POLLIN)) {
            dbus_service::process_pending(g_session_dbus);
        }

        // Process system D-Bus (BlueZ signals)
        if (fds.size() > 1 && (fds[1].revents & POLLIN)) {
            dbus_connection_read_write(g_system_dbus, 0);
            while (dbus_connection_dispatch(g_system_dbus) == DBUS_DISPATCH_DATA_REMAINS) {}
        }

        // Process L2CAP data
        if (l2cap_fd_idx >= 0 && (fds[l2cap_fd_idx].revents & POLLIN)) {
            auto data = l2cap::recv(g_connection);
            if (!data.empty()) {
                handle_packet(data);
            }
        }

        // Check for L2CAP errors (disconnect)
        if (l2cap_fd_idx >= 0 && (fds[l2cap_fd_idx].revents & (POLLERR | POLLHUP))) {
            std::cout << "Connection lost" << std::endl;
            disconnect_airpods();
        }
    }
}

// ============================================================================
// Subcommand implementations
// ============================================================================

static int cmd_daemon() {
    // Set up signal handlers
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    std::cout << "AirPods daemon starting..." << std::endl;

    // Connect to system D-Bus (for BlueZ)
    DBusError err;
    dbus_error_init(&err);

    g_system_dbus = dbus_bus_get(DBUS_BUS_SYSTEM, &err);
    if (dbus_error_is_set(&err)) {
        std::cerr << "Failed to connect to system D-Bus: " << err.message << std::endl;
        dbus_error_free(&err);
        return 1;
    }

    // Set up D-Bus service callbacks
    g_dbus_callbacks.on_pair = []() {
        std::cout << "Starting discovery for pairing..." << std::endl;
        g_pairing_mode = true;
        bluez::start_discovery(g_system_dbus);

        // Also check for already-discovered but unpaired AirPods
        auto unpaired = bluez::find_unpaired_airpods(g_system_dbus);
        for (const auto& dev : unpaired) {
            std::cout << "Found already-discovered AirPods: " << dev.name
                      << " (" << dev.address << ")" << std::endl;
            std::cout << "Pairing with " << dev.address << "..." << std::endl;
            if (bluez::pair_device(g_system_dbus, dev.path)) {
                std::cout << "Pairing initiated" << std::endl;
                bluez::stop_discovery(g_system_dbus);
                g_pairing_mode = false;
                return;
            }
        }
    };

    g_dbus_callbacks.on_connect = []() {
        auto airpods = bluez::find_connected_airpods(g_system_dbus);
        if (airpods) {
            connect_airpods(airpods->address);
        } else {
            auto devices = bluez::find_paired_airpods(g_system_dbus);
            if (!devices.empty()) {
                bluez::connect_device(g_system_dbus, devices[0].path);
            }
        }
    };

    g_dbus_callbacks.on_disconnect = []() {
        disconnect_airpods();
    };

    g_dbus_callbacks.on_set_noise_control = [](airpods::NoiseControlMode mode) {
        set_noise_control(mode);
    };

    // Set up BlueZ callbacks for auto-connect
    g_bluez_callbacks.on_airpods_found = [](const bluez::DeviceInfo& info) {
        std::cout << "Found AirPods: " << info.name << " (" << info.address << ")" << std::endl;

        if (g_pairing_mode && !info.paired) {
            // Only pair when explicitly requested via Pair()
            std::cout << "Pairing with " << info.address << "..." << std::endl;
            if (bluez::pair_device(g_system_dbus, info.path)) {
                std::cout << "Pairing initiated" << std::endl;
                // Trust the device for auto-reconnect
                bluez::trust_device(g_system_dbus, info.path);
                bluez::stop_discovery(g_system_dbus);
                g_pairing_mode = false;
                // Connection will happen via on_device_connected callback
            } else {
                std::cerr << "Pairing failed" << std::endl;
            }
        }
        // Auto-connect only happens via on_device_connected for paired devices
    };

    g_bluez_callbacks.on_device_connected = [](const std::string& address) {
        std::cout << "AirPods Bluetooth connected: " << address << std::endl;
        // Auto-connect L2CAP when Bluetooth connects
        connect_airpods(address);
    };

    g_bluez_callbacks.on_device_disconnected = [](const std::string& address) {
        std::cout << "AirPods Bluetooth disconnected: " << address << std::endl;
        disconnect_airpods();
    };

    // Set up BlueZ signal handlers and filter
    bluez::setup_signal_handlers(g_system_dbus, &g_bluez_callbacks);
    dbus_connection_add_filter(g_system_dbus, bluez_filter, &g_bluez_callbacks, nullptr);

    // Initialize session D-Bus service
    g_session_dbus = dbus_service::init(&g_dbus_callbacks, &g_dbus_state);
    if (!g_session_dbus) {
        std::cerr << "Failed to initialize D-Bus service" << std::endl;
        return 1;
    }

    if (!dbus_service::request_name(g_session_dbus)) {
        std::cerr << "Failed to request D-Bus name" << std::endl;
        return 1;
    }

    // Auto-connect: check for already-connected AirPods
    auto existing = bluez::find_connected_airpods(g_system_dbus);
    if (existing) {
        std::cout << "Found already connected AirPods: " << existing->name << std::endl;
        connect_airpods(existing->address);
    } else {
        // Try to connect to first paired AirPods
        auto paired = bluez::find_paired_airpods(g_system_dbus);
        if (!paired.empty()) {
            std::cout << "Found paired AirPods: " << paired[0].name << ", connecting..." << std::endl;
            bluez::connect_device(g_system_dbus, paired[0].path);
        }
    }

    std::cout << "Daemon ready. D-Bus service: " << dbus_service::SERVICE_NAME << std::endl;

    // Run event loop
    run_event_loop();

    // Cleanup
    dbus_connection_remove_filter(g_system_dbus, bluez_filter, &g_bluez_callbacks);
    dbus_service::cleanup(g_session_dbus);
    dbus_connection_unref(g_system_dbus);

    std::cout << "Daemon stopped" << std::endl;
    return 0;
}

// Helper to get a string property from the daemon
static std::string get_daemon_string_prop(DBusConnection* conn, const char* prop) {
    DBusError err;
    dbus_error_init(&err);

    DBusMessage* msg = dbus_message_new_method_call(
        dbus_service::SERVICE_NAME,
        dbus_service::OBJECT_PATH,
        "org.freedesktop.DBus.Properties",
        "Get"
    );
    if (!msg) return "";

    const char* iface = dbus_service::INTERFACE_NAME;
    dbus_message_append_args(msg, DBUS_TYPE_STRING, &iface,
                             DBUS_TYPE_STRING, &prop, DBUS_TYPE_INVALID);

    DBusMessage* reply = dbus_connection_send_with_reply_and_block(conn, msg, 1000, &err);
    dbus_message_unref(msg);

    if (dbus_error_is_set(&err)) {
        dbus_error_free(&err);
        return "";
    }

    std::string result;
    if (reply) {
        DBusMessageIter iter, variant;
        if (dbus_message_iter_init(reply, &iter) &&
            dbus_message_iter_get_arg_type(&iter) == DBUS_TYPE_VARIANT) {
            dbus_message_iter_recurse(&iter, &variant);
            if (dbus_message_iter_get_arg_type(&variant) == DBUS_TYPE_STRING) {
                const char* val;
                dbus_message_iter_get_basic(&variant, &val);
                result = val;
            }
        }
        dbus_message_unref(reply);
    }
    return result;
}

// Helper to get a bool property from the daemon
static bool get_daemon_bool_prop(DBusConnection* conn, const char* prop) {
    DBusError err;
    dbus_error_init(&err);

    DBusMessage* msg = dbus_message_new_method_call(
        dbus_service::SERVICE_NAME,
        dbus_service::OBJECT_PATH,
        "org.freedesktop.DBus.Properties",
        "Get"
    );
    if (!msg) return false;

    const char* iface = dbus_service::INTERFACE_NAME;
    dbus_message_append_args(msg, DBUS_TYPE_STRING, &iface,
                             DBUS_TYPE_STRING, &prop, DBUS_TYPE_INVALID);

    DBusMessage* reply = dbus_connection_send_with_reply_and_block(conn, msg, 1000, &err);
    dbus_message_unref(msg);

    if (dbus_error_is_set(&err)) {
        dbus_error_free(&err);
        return false;
    }

    bool result = false;
    if (reply) {
        DBusMessageIter iter, variant;
        if (dbus_message_iter_init(reply, &iter) &&
            dbus_message_iter_get_arg_type(&iter) == DBUS_TYPE_VARIANT) {
            dbus_message_iter_recurse(&iter, &variant);
            if (dbus_message_iter_get_arg_type(&variant) == DBUS_TYPE_BOOLEAN) {
                dbus_bool_t val;
                dbus_message_iter_get_basic(&variant, &val);
                result = val;
            }
        }
        dbus_message_unref(reply);
    }
    return result;
}

static int cmd_pair() {
    DBusError err;
    dbus_error_init(&err);

    DBusConnection* conn = dbus_bus_get(DBUS_BUS_SESSION, &err);
    if (dbus_error_is_set(&err)) {
        std::cerr << "Failed to connect to session D-Bus: " << err.message << std::endl;
        dbus_error_free(&err);
        return 1;
    }

    // Call Pair() on the daemon
    DBusMessage* msg = dbus_message_new_method_call(
        dbus_service::SERVICE_NAME,
        dbus_service::OBJECT_PATH,
        dbus_service::INTERFACE_NAME,
        "Pair"
    );
    if (!msg) {
        std::cerr << "Failed to create D-Bus message" << std::endl;
        dbus_connection_unref(conn);
        return 1;
    }

    DBusMessage* reply = dbus_connection_send_with_reply_and_block(conn, msg, 5000, &err);
    dbus_message_unref(msg);

    if (dbus_error_is_set(&err)) {
        std::cerr << "Pair failed (is daemon running?): " << err.message << std::endl;
        dbus_error_free(&err);
        dbus_connection_unref(conn);
        return 1;
    }
    if (reply) dbus_message_unref(reply);

    std::cout << "Searching for AirPods...\n"
              << "Put AirPods in pairing mode: open the case lid, then press and hold\n"
              << "the button on the back (or touch and hold the front status light on\n"
              << "newer models) until the light flashes white.\n" << std::endl;

    // Poll for connection with timeout (60 seconds)
    constexpr int timeout_seconds = 60;
    constexpr int poll_interval_ms = 500;
    int elapsed_ms = 0;

    while (elapsed_ms < timeout_seconds * 1000) {
        usleep(poll_interval_ms * 1000);
        elapsed_ms += poll_interval_ms;

        // Check if connected
        if (get_daemon_bool_prop(conn, "Connected")) {
            // Get device info
            std::string name = get_daemon_string_prop(conn, "DeviceName");
            std::string model = get_daemon_string_prop(conn, "Model");

            std::cout << "Paired and connected!" << std::endl;
            std::cout << "  Device: " << (name.empty() ? "(unknown)" : name) << std::endl;
            std::cout << "  Model:  " << (model.empty() ? "(unknown)" : model) << std::endl;

            dbus_connection_unref(conn);
            return 0;
        }

        // Print progress dot every 2 seconds
        if ((elapsed_ms % 2000) == 0) {
            std::cout << "." << std::flush;
        }
    }

    std::cerr << "\nTimeout waiting for AirPods to pair" << std::endl;
    dbus_connection_unref(conn);
    return 1;
}

static int cmd_status() {
    DBusError err;
    dbus_error_init(&err);

    DBusConnection* conn = dbus_bus_get(DBUS_BUS_SESSION, &err);
    if (dbus_error_is_set(&err)) {
        std::cerr << "Failed to connect to session D-Bus: " << err.message << std::endl;
        dbus_error_free(&err);
        return 1;
    }

    // Get all properties
    DBusMessage* msg = dbus_message_new_method_call(
        dbus_service::SERVICE_NAME,
        dbus_service::OBJECT_PATH,
        "org.freedesktop.DBus.Properties",
        "GetAll"
    );
    if (!msg) {
        dbus_connection_unref(conn);
        return 1;
    }

    const char* iface = dbus_service::INTERFACE_NAME;
    dbus_message_append_args(msg, DBUS_TYPE_STRING, &iface, DBUS_TYPE_INVALID);

    DBusMessage* reply = dbus_connection_send_with_reply_and_block(conn, msg, 2000, &err);
    dbus_message_unref(msg);

    if (dbus_error_is_set(&err)) {
        std::cerr << "Failed to get status (is daemon running?): " << err.message << std::endl;
        dbus_error_free(&err);
        dbus_connection_unref(conn);
        return 1;
    }

    if (reply) {
        DBusMessageIter iter, dict;
        if (dbus_message_iter_init(reply, &iter) &&
            dbus_message_iter_get_arg_type(&iter) == DBUS_TYPE_ARRAY) {

            dbus_message_iter_recurse(&iter, &dict);

            while (dbus_message_iter_get_arg_type(&dict) == DBUS_TYPE_DICT_ENTRY) {
                DBusMessageIter entry, variant;
                dbus_message_iter_recurse(&dict, &entry);

                const char* prop_name;
                dbus_message_iter_get_basic(&entry, &prop_name);
                dbus_message_iter_next(&entry);
                dbus_message_iter_recurse(&entry, &variant);

                int type = dbus_message_iter_get_arg_type(&variant);
                if (type == DBUS_TYPE_STRING) {
                    const char* val;
                    dbus_message_iter_get_basic(&variant, &val);
                    std::cout << prop_name << ": " << val << std::endl;
                } else if (type == DBUS_TYPE_BOOLEAN) {
                    dbus_bool_t val;
                    dbus_message_iter_get_basic(&variant, &val);
                    std::cout << prop_name << ": " << (val ? "true" : "false") << std::endl;
                } else if (type == DBUS_TYPE_BYTE) {
                    uint8_t val;
                    dbus_message_iter_get_basic(&variant, &val);
                    std::cout << prop_name << ": " << static_cast<int>(val) << std::endl;
                } else if (type == DBUS_TYPE_INT32) {
                    dbus_int32_t val;
                    dbus_message_iter_get_basic(&variant, &val);
                    std::cout << prop_name << ": " << val << std::endl;
                }

                dbus_message_iter_next(&dict);
            }
        }
        dbus_message_unref(reply);
    }

    dbus_connection_unref(conn);
    return 0;
}

static int cmd_set_noise_control(const char* mode_str) {
    auto mode = airpods::noise_control_mode_from_string(mode_str);
    if (!mode) {
        std::cerr << "Invalid mode: " << mode_str << std::endl;
        std::cerr << "Valid modes: off, anc, transparency, adaptive" << std::endl;
        return 1;
    }

    DBusError err;
    dbus_error_init(&err);

    DBusConnection* conn = dbus_bus_get(DBUS_BUS_SESSION, &err);
    if (dbus_error_is_set(&err)) {
        std::cerr << "Failed to connect to session D-Bus: " << err.message << std::endl;
        dbus_error_free(&err);
        return 1;
    }

    DBusMessage* msg = dbus_message_new_method_call(
        dbus_service::SERVICE_NAME,
        dbus_service::OBJECT_PATH,
        dbus_service::INTERFACE_NAME,
        "SetNoiseControl"
    );
    if (!msg) {
        dbus_connection_unref(conn);
        return 1;
    }

    dbus_message_append_args(msg, DBUS_TYPE_STRING, &mode_str, DBUS_TYPE_INVALID);

    DBusMessage* reply = dbus_connection_send_with_reply_and_block(conn, msg, 2000, &err);
    dbus_message_unref(msg);

    if (dbus_error_is_set(&err)) {
        std::cerr << "SetNoiseControl failed: " << err.message << std::endl;
        dbus_error_free(&err);
        dbus_connection_unref(conn);
        return 1;
    }

    if (reply) dbus_message_unref(reply);
    dbus_connection_unref(conn);

    std::cout << "Noise control set to: " << mode_str << std::endl;
    return 0;
}

static void print_usage(const char* prog) {
    std::cerr << "Usage: " << prog << " <command> [options]\n"
              << "\n"
              << "Commands:\n"
              << "  daemon              Run the AirPods daemon\n"
              << "  pair                Start pairing mode\n"
              << "  status              Show current status\n"
              << "  noise <mode>        Set noise control (off, anc, transparency, adaptive)\n"
              << "  help                Show this help\n";
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    std::string cmd = argv[1];

    if (cmd == "daemon") {
        return cmd_daemon();
    } else if (cmd == "pair") {
        return cmd_pair();
    } else if (cmd == "status") {
        return cmd_status();
    } else if (cmd == "noise" || cmd == "anc") {
        if (argc < 3) {
            std::cerr << "Usage: " << argv[0] << " noise <mode>\n";
            std::cerr << "Modes: off, anc, transparency, adaptive\n";
            return 1;
        }
        return cmd_set_noise_control(argv[2]);
    } else if (cmd == "help" || cmd == "--help" || cmd == "-h") {
        print_usage(argv[0]);
        return 0;
    } else {
        std::cerr << "Unknown command: " << cmd << std::endl;
        print_usage(argv[0]);
        return 1;
    }
}
