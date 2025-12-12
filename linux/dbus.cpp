#include "dbus.hpp"
#include <cstring>
#include <iostream>
#include <vector>

namespace dbus_service {

// Global pointers for callbacks (set in init)
static Callbacks* g_callbacks = nullptr;
static State* g_state = nullptr;

// Introspection XML
static const char* INTROSPECT_XML =
    "<!DOCTYPE node PUBLIC \"-//freedesktop//DTD D-BUS Object Introspection 1.0//EN\"\n"
    "\"http://www.freedesktop.org/standards/dbus/1.0/introspect.dtd\">\n"
    "<node>\n"
    "  <interface name=\"com.apple.Airpods\">\n"
    "    <method name=\"Pair\"/>\n"
    "    <method name=\"Connect\"/>\n"
    "    <method name=\"Disconnect\"/>\n"
    "    <method name=\"SetNoiseControl\">\n"
    "      <arg name=\"mode\" type=\"s\" direction=\"in\"/>\n"
    "    </method>\n"
    "    <property name=\"Connected\" type=\"b\" access=\"read\"/>\n"
    "    <property name=\"NoiseControlMode\" type=\"s\" access=\"readwrite\"/>\n"
    "    <property name=\"DeviceName\" type=\"s\" access=\"read\"/>\n"
    "    <property name=\"Model\" type=\"s\" access=\"read\"/>\n"
    "    <property name=\"BatteryLeft\" type=\"i\" access=\"read\"/>\n"
    "    <property name=\"BatteryRight\" type=\"i\" access=\"read\"/>\n"
    "    <property name=\"BatteryCase\" type=\"i\" access=\"read\"/>\n"
    "    <property name=\"ChargingLeft\" type=\"b\" access=\"read\"/>\n"
    "    <property name=\"ChargingRight\" type=\"b\" access=\"read\"/>\n"
    "    <property name=\"ChargingCase\" type=\"b\" access=\"read\"/>\n"
    "    <property name=\"LeftInEar\" type=\"b\" access=\"read\"/>\n"
    "    <property name=\"RightInEar\" type=\"b\" access=\"read\"/>\n"
    "  </interface>\n"
    "  <interface name=\"org.freedesktop.DBus.Properties\">\n"
    "    <method name=\"Get\">\n"
    "      <arg name=\"interface\" type=\"s\" direction=\"in\"/>\n"
    "      <arg name=\"property\" type=\"s\" direction=\"in\"/>\n"
    "      <arg name=\"value\" type=\"v\" direction=\"out\"/>\n"
    "    </method>\n"
    "    <method name=\"Set\">\n"
    "      <arg name=\"interface\" type=\"s\" direction=\"in\"/>\n"
    "      <arg name=\"property\" type=\"s\" direction=\"in\"/>\n"
    "      <arg name=\"value\" type=\"v\" direction=\"in\"/>\n"
    "    </method>\n"
    "    <method name=\"GetAll\">\n"
    "      <arg name=\"interface\" type=\"s\" direction=\"in\"/>\n"
    "      <arg name=\"properties\" type=\"a{sv}\" direction=\"out\"/>\n"
    "    </method>\n"
    "    <signal name=\"PropertiesChanged\">\n"
    "      <arg name=\"interface\" type=\"s\"/>\n"
    "      <arg name=\"changed_properties\" type=\"a{sv}\"/>\n"
    "      <arg name=\"invalidated_properties\" type=\"as\"/>\n"
    "    </signal>\n"
    "  </interface>\n"
    "  <interface name=\"org.freedesktop.DBus.Introspectable\">\n"
    "    <method name=\"Introspect\">\n"
    "      <arg name=\"xml\" type=\"s\" direction=\"out\"/>\n"
    "    </method>\n"
    "  </interface>\n"
    "</node>\n";

// Helper to append variant with string
static void append_variant_string(DBusMessageIter* iter, const char* value) {
    DBusMessageIter variant;
    dbus_message_iter_open_container(iter, DBUS_TYPE_VARIANT, "s", &variant);
    dbus_message_iter_append_basic(&variant, DBUS_TYPE_STRING, &value);
    dbus_message_iter_close_container(iter, &variant);
}

// Helper to append variant with bool
static void append_variant_bool(DBusMessageIter* iter, dbus_bool_t value) {
    DBusMessageIter variant;
    dbus_message_iter_open_container(iter, DBUS_TYPE_VARIANT, "b", &variant);
    dbus_message_iter_append_basic(&variant, DBUS_TYPE_BOOLEAN, &value);
    dbus_message_iter_close_container(iter, &variant);
}

// Helper to append variant with int32
static void append_variant_int32(DBusMessageIter* iter, dbus_int32_t value) {
    DBusMessageIter variant;
    dbus_message_iter_open_container(iter, DBUS_TYPE_VARIANT, "i", &variant);
    dbus_message_iter_append_basic(&variant, DBUS_TYPE_INT32, &value);
    dbus_message_iter_close_container(iter, &variant);
}

// Handle Get property
static DBusMessage* handle_get(DBusMessage* msg, const State& state) {
    const char* iface;
    const char* prop;

    if (!dbus_message_get_args(msg, nullptr,
            DBUS_TYPE_STRING, &iface,
            DBUS_TYPE_STRING, &prop,
            DBUS_TYPE_INVALID)) {
        return dbus_message_new_error(msg, DBUS_ERROR_INVALID_ARGS, "Invalid arguments");
    }

    if (strcmp(iface, INTERFACE_NAME) != 0) {
        return dbus_message_new_error(msg, DBUS_ERROR_UNKNOWN_INTERFACE, "Unknown interface");
    }

    DBusMessage* reply = dbus_message_new_method_return(msg);
    DBusMessageIter iter;
    dbus_message_iter_init_append(reply, &iter);

    if (strcmp(prop, "Connected") == 0) {
        dbus_bool_t val = state.connected;
        append_variant_bool(&iter, val);
    } else if (strcmp(prop, "NoiseControlMode") == 0) {
        const char* val = state.noise_control_mode.c_str();
        append_variant_string(&iter, val);
    } else if (strcmp(prop, "DeviceName") == 0) {
        const char* val = state.device_name.c_str();
        append_variant_string(&iter, val);
    } else if (strcmp(prop, "Model") == 0) {
        const char* val = state.model.c_str();
        append_variant_string(&iter, val);
    } else if (strcmp(prop, "BatteryLeft") == 0) {
        append_variant_int32(&iter, state.battery_left);
    } else if (strcmp(prop, "BatteryRight") == 0) {
        append_variant_int32(&iter, state.battery_right);
    } else if (strcmp(prop, "BatteryCase") == 0) {
        append_variant_int32(&iter, state.battery_case);
    } else if (strcmp(prop, "ChargingLeft") == 0) {
        dbus_bool_t val = state.charging_left;
        append_variant_bool(&iter, val);
    } else if (strcmp(prop, "ChargingRight") == 0) {
        dbus_bool_t val = state.charging_right;
        append_variant_bool(&iter, val);
    } else if (strcmp(prop, "ChargingCase") == 0) {
        dbus_bool_t val = state.charging_case;
        append_variant_bool(&iter, val);
    } else if (strcmp(prop, "LeftInEar") == 0) {
        dbus_bool_t val = state.left_in_ear;
        append_variant_bool(&iter, val);
    } else if (strcmp(prop, "RightInEar") == 0) {
        dbus_bool_t val = state.right_in_ear;
        append_variant_bool(&iter, val);
    } else {
        dbus_message_unref(reply);
        return dbus_message_new_error(msg, DBUS_ERROR_UNKNOWN_PROPERTY, "Unknown property");
    }

    return reply;
}

// Handle GetAll properties
static DBusMessage* handle_get_all(DBusMessage* msg, const State& state) {
    const char* iface;

    if (!dbus_message_get_args(msg, nullptr,
            DBUS_TYPE_STRING, &iface,
            DBUS_TYPE_INVALID)) {
        return dbus_message_new_error(msg, DBUS_ERROR_INVALID_ARGS, "Invalid arguments");
    }

    if (strcmp(iface, INTERFACE_NAME) != 0) {
        return dbus_message_new_error(msg, DBUS_ERROR_UNKNOWN_INTERFACE, "Unknown interface");
    }

    DBusMessage* reply = dbus_message_new_method_return(msg);
    DBusMessageIter iter, dict, entry;
    dbus_message_iter_init_append(reply, &iter);
    dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY, "{sv}", &dict);

    // Connected
    {
        dbus_message_iter_open_container(&dict, DBUS_TYPE_DICT_ENTRY, nullptr, &entry);
        const char* name = "Connected";
        dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &name);
        dbus_bool_t val = state.connected;
        append_variant_bool(&entry, val);
        dbus_message_iter_close_container(&dict, &entry);
    }
    // NoiseControlMode
    {
        dbus_message_iter_open_container(&dict, DBUS_TYPE_DICT_ENTRY, nullptr, &entry);
        const char* name = "NoiseControlMode";
        dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &name);
        const char* val = state.noise_control_mode.c_str();
        append_variant_string(&entry, val);
        dbus_message_iter_close_container(&dict, &entry);
    }
    // DeviceName
    {
        dbus_message_iter_open_container(&dict, DBUS_TYPE_DICT_ENTRY, nullptr, &entry);
        const char* name = "DeviceName";
        dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &name);
        const char* val = state.device_name.c_str();
        append_variant_string(&entry, val);
        dbus_message_iter_close_container(&dict, &entry);
    }
    // Model
    {
        dbus_message_iter_open_container(&dict, DBUS_TYPE_DICT_ENTRY, nullptr, &entry);
        const char* name = "Model";
        dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &name);
        const char* val = state.model.c_str();
        append_variant_string(&entry, val);
        dbus_message_iter_close_container(&dict, &entry);
    }
    // BatteryLeft
    {
        dbus_message_iter_open_container(&dict, DBUS_TYPE_DICT_ENTRY, nullptr, &entry);
        const char* name = "BatteryLeft";
        dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &name);
        append_variant_int32(&entry, state.battery_left);
        dbus_message_iter_close_container(&dict, &entry);
    }
    // BatteryRight
    {
        dbus_message_iter_open_container(&dict, DBUS_TYPE_DICT_ENTRY, nullptr, &entry);
        const char* name = "BatteryRight";
        dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &name);
        append_variant_int32(&entry, state.battery_right);
        dbus_message_iter_close_container(&dict, &entry);
    }
    // BatteryCase
    {
        dbus_message_iter_open_container(&dict, DBUS_TYPE_DICT_ENTRY, nullptr, &entry);
        const char* name = "BatteryCase";
        dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &name);
        append_variant_int32(&entry, state.battery_case);
        dbus_message_iter_close_container(&dict, &entry);
    }
    // LeftInEar
    {
        dbus_message_iter_open_container(&dict, DBUS_TYPE_DICT_ENTRY, nullptr, &entry);
        const char* name = "LeftInEar";
        dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &name);
        dbus_bool_t val = state.left_in_ear;
        append_variant_bool(&entry, val);
        dbus_message_iter_close_container(&dict, &entry);
    }
    // RightInEar
    {
        dbus_message_iter_open_container(&dict, DBUS_TYPE_DICT_ENTRY, nullptr, &entry);
        const char* name = "RightInEar";
        dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &name);
        dbus_bool_t val = state.right_in_ear;
        append_variant_bool(&entry, val);
        dbus_message_iter_close_container(&dict, &entry);
    }

    dbus_message_iter_close_container(&iter, &dict);
    return reply;
}

// Handle Set property
static DBusMessage* handle_set(DBusMessage* msg, Callbacks* callbacks) {
    const char* iface;
    const char* prop;

    DBusMessageIter iter;
    if (!dbus_message_iter_init(msg, &iter)) {
        return dbus_message_new_error(msg, DBUS_ERROR_INVALID_ARGS, "No arguments");
    }

    dbus_message_iter_get_basic(&iter, &iface);
    dbus_message_iter_next(&iter);
    dbus_message_iter_get_basic(&iter, &prop);
    dbus_message_iter_next(&iter);

    if (strcmp(iface, INTERFACE_NAME) != 0) {
        return dbus_message_new_error(msg, DBUS_ERROR_UNKNOWN_INTERFACE, "Unknown interface");
    }

    if (strcmp(prop, "NoiseControlMode") == 0) {
        DBusMessageIter variant;
        dbus_message_iter_recurse(&iter, &variant);

        if (dbus_message_iter_get_arg_type(&variant) == DBUS_TYPE_STRING) {
            const char* mode;
            dbus_message_iter_get_basic(&variant, &mode);

            auto parsed = airpods::noise_control_mode_from_string(mode);
            if (parsed && callbacks && callbacks->on_set_noise_control) {
                callbacks->on_set_noise_control(*parsed);
            }
        }
        return dbus_message_new_method_return(msg);
    }

    return dbus_message_new_error(msg, DBUS_ERROR_PROPERTY_READ_ONLY, "Property is read-only");
}

// Message handler
static DBusHandlerResult message_handler(DBusConnection* conn, DBusMessage* msg, void* data) {
    (void)data;

    const char* iface = dbus_message_get_interface(msg);
    const char* member = dbus_message_get_member(msg);
    const char* path = dbus_message_get_path(msg);

    if (!path || strcmp(path, OBJECT_PATH) != 0) {
        return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
    }

    DBusMessage* reply = nullptr;

    // Introspection
    if (iface && strcmp(iface, "org.freedesktop.DBus.Introspectable") == 0 &&
        member && strcmp(member, "Introspect") == 0) {
        reply = dbus_message_new_method_return(msg);
        dbus_message_append_args(reply, DBUS_TYPE_STRING, &INTROSPECT_XML, DBUS_TYPE_INVALID);
    }
    // Properties
    else if (iface && strcmp(iface, "org.freedesktop.DBus.Properties") == 0) {
        if (member && strcmp(member, "Get") == 0) {
            reply = handle_get(msg, *g_state);
        } else if (member && strcmp(member, "GetAll") == 0) {
            reply = handle_get_all(msg, *g_state);
        } else if (member && strcmp(member, "Set") == 0) {
            reply = handle_set(msg, g_callbacks);
        }
    }
    // Our interface methods
    else if (iface && strcmp(iface, INTERFACE_NAME) == 0) {
        if (member && strcmp(member, "Pair") == 0) {
            std::cout << "dbus: Pair() called" << std::endl;
            if (g_callbacks && g_callbacks->on_pair) g_callbacks->on_pair();
            reply = dbus_message_new_method_return(msg);
        } else if (member && strcmp(member, "Connect") == 0) {
            std::cout << "dbus: Connect() called" << std::endl;
            if (g_callbacks && g_callbacks->on_connect) g_callbacks->on_connect();
            reply = dbus_message_new_method_return(msg);
        } else if (member && strcmp(member, "Disconnect") == 0) {
            std::cout << "dbus: Disconnect() called" << std::endl;
            if (g_callbacks && g_callbacks->on_disconnect) g_callbacks->on_disconnect();
            reply = dbus_message_new_method_return(msg);
        } else if (member && strcmp(member, "SetNoiseControl") == 0) {
            const char* mode;
            if (dbus_message_get_args(msg, nullptr, DBUS_TYPE_STRING, &mode, DBUS_TYPE_INVALID)) {
                std::cout << "dbus: SetNoiseControl(" << mode << ") called" << std::endl;
                auto parsed = airpods::noise_control_mode_from_string(mode);
                if (parsed && g_callbacks && g_callbacks->on_set_noise_control) {
                    g_callbacks->on_set_noise_control(*parsed);
                }
                reply = dbus_message_new_method_return(msg);
            } else {
                reply = dbus_message_new_error(msg, DBUS_ERROR_INVALID_ARGS, "Expected string argument");
            }
        }
    }

    if (reply) {
        dbus_connection_send(conn, reply, nullptr);
        dbus_message_unref(reply);
        return DBUS_HANDLER_RESULT_HANDLED;
    }

    return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

DBusConnection* init(Callbacks* callbacks, State* state) {
    g_callbacks = callbacks;
    g_state = state;

    DBusError err;
    dbus_error_init(&err);

    DBusConnection* conn = dbus_bus_get(DBUS_BUS_SESSION, &err);
    if (dbus_error_is_set(&err)) {
        std::cerr << "dbus: connection error: " << err.message << std::endl;
        dbus_error_free(&err);
        return nullptr;
    }

    // Register object path
    DBusObjectPathVTable vtable = {};
    vtable.message_function = message_handler;

    if (!dbus_connection_register_object_path(conn, OBJECT_PATH, &vtable, nullptr)) {
        std::cerr << "dbus: failed to register object path" << std::endl;
        return nullptr;
    }

    return conn;
}

bool request_name(DBusConnection* conn) {
    DBusError err;
    dbus_error_init(&err);

    int ret = dbus_bus_request_name(conn, SERVICE_NAME, DBUS_NAME_FLAG_REPLACE_EXISTING, &err);
    if (dbus_error_is_set(&err)) {
        std::cerr << "dbus: name error: " << err.message << std::endl;
        dbus_error_free(&err);
        return false;
    }

    if (ret != DBUS_REQUEST_NAME_REPLY_PRIMARY_OWNER) {
        std::cerr << "dbus: not primary owner of " << SERVICE_NAME << std::endl;
        return false;
    }

    std::cout << "dbus: registered service " << SERVICE_NAME << std::endl;
    return true;
}

void emit_properties_changed(DBusConnection* conn, const State& state,
                              const char** property_names, int num_properties) {
    DBusMessage* signal = dbus_message_new_signal(OBJECT_PATH,
        "org.freedesktop.DBus.Properties", "PropertiesChanged");
    if (!signal) return;

    DBusMessageIter iter, dict, entry;
    dbus_message_iter_init_append(signal, &iter);

    // Interface name
    const char* iface = INTERFACE_NAME;
    dbus_message_iter_append_basic(&iter, DBUS_TYPE_STRING, &iface);

    // Changed properties dict
    dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY, "{sv}", &dict);

    for (int i = 0; i < num_properties; i++) {
        const char* prop = property_names[i];
        dbus_message_iter_open_container(&dict, DBUS_TYPE_DICT_ENTRY, nullptr, &entry);
        dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &prop);

        if (strcmp(prop, "Connected") == 0) {
            dbus_bool_t val = state.connected;
            append_variant_bool(&entry, val);
        } else if (strcmp(prop, "NoiseControlMode") == 0) {
            const char* val = state.noise_control_mode.c_str();
            append_variant_string(&entry, val);
        } else if (strcmp(prop, "DeviceName") == 0) {
            const char* val = state.device_name.c_str();
            append_variant_string(&entry, val);
        } else if (strcmp(prop, "Model") == 0) {
            const char* val = state.model.c_str();
            append_variant_string(&entry, val);
        } else if (strcmp(prop, "BatteryLeft") == 0) {
            append_variant_int32(&entry, state.battery_left);
        } else if (strcmp(prop, "BatteryRight") == 0) {
            append_variant_int32(&entry, state.battery_right);
        } else if (strcmp(prop, "BatteryCase") == 0) {
            append_variant_int32(&entry, state.battery_case);
        } else if (strcmp(prop, "ChargingLeft") == 0) {
            dbus_bool_t val = state.charging_left;
            append_variant_bool(&entry, val);
        } else if (strcmp(prop, "ChargingRight") == 0) {
            dbus_bool_t val = state.charging_right;
            append_variant_bool(&entry, val);
        } else if (strcmp(prop, "ChargingCase") == 0) {
            dbus_bool_t val = state.charging_case;
            append_variant_bool(&entry, val);
        } else if (strcmp(prop, "LeftInEar") == 0) {
            dbus_bool_t val = state.left_in_ear;
            append_variant_bool(&entry, val);
        } else if (strcmp(prop, "RightInEar") == 0) {
            dbus_bool_t val = state.right_in_ear;
            append_variant_bool(&entry, val);
        }

        dbus_message_iter_close_container(&dict, &entry);
    }
    dbus_message_iter_close_container(&iter, &dict);

    // Invalidated properties (empty array)
    DBusMessageIter invalidated;
    dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY, "s", &invalidated);
    dbus_message_iter_close_container(&iter, &invalidated);

    dbus_connection_send(conn, signal, nullptr);
    dbus_message_unref(signal);
}

void update_from_device_state(DBusConnection* conn, State* state,
                               const airpods::DeviceState& device) {
    std::vector<const char*> changed;

    if (state->connected != device.connected) {
        state->connected = device.connected;
        changed.push_back("Connected");
    }

    std::string new_mode(airpods::to_string(device.noise_control_mode));
    if (state->noise_control_mode != new_mode) {
        state->noise_control_mode = new_mode;
        changed.push_back("NoiseControlMode");
    }

    if (state->device_name != device.device_name) {
        state->device_name = device.device_name;
        changed.push_back("DeviceName");
    }

    std::string new_model(airpods::to_string(device.model));
    if (state->model != new_model) {
        state->model = new_model;
        changed.push_back("Model");
    }

    int32_t new_left = device.battery.left.available ? device.battery.left.level : -1;
    int32_t new_right = device.battery.right.available ? device.battery.right.level : -1;
    int32_t new_case = device.battery.case_.available ? device.battery.case_.level : -1;

    if (state->battery_left != new_left) { state->battery_left = new_left; changed.push_back("BatteryLeft"); }
    if (state->battery_right != new_right) { state->battery_right = new_right; changed.push_back("BatteryRight"); }
    if (state->battery_case != new_case) { state->battery_case = new_case; changed.push_back("BatteryCase"); }
    if (state->charging_left != device.battery.left.charging) { state->charging_left = device.battery.left.charging; changed.push_back("ChargingLeft"); }
    if (state->charging_right != device.battery.right.charging) { state->charging_right = device.battery.right.charging; changed.push_back("ChargingRight"); }
    if (state->charging_case != device.battery.case_.charging) { state->charging_case = device.battery.case_.charging; changed.push_back("ChargingCase"); }

    bool new_left_ear = device.ear_detection.primary_in_ear();
    bool new_right_ear = device.ear_detection.secondary_in_ear();
    if (!device.battery.left_is_primary) std::swap(new_left_ear, new_right_ear);

    if (state->left_in_ear != new_left_ear) { state->left_in_ear = new_left_ear; changed.push_back("LeftInEar"); }
    if (state->right_in_ear != new_right_ear) { state->right_in_ear = new_right_ear; changed.push_back("RightInEar"); }

    if (!changed.empty()) {
        emit_properties_changed(conn, *state, changed.data(), static_cast<int>(changed.size()));
    }
}

void process_pending(DBusConnection* conn) {
    dbus_connection_read_write(conn, 0);
    while (dbus_connection_dispatch(conn) == DBUS_DISPATCH_DATA_REMAINS) {
        // Keep processing
    }
}

int get_fd(DBusConnection* conn) {
    int fd = -1;
    if (!dbus_connection_get_unix_fd(conn, &fd)) {
        return -1;
    }
    return fd;
}

void cleanup(DBusConnection* conn) {
    if (conn) {
        dbus_connection_unref(conn);
    }
    g_callbacks = nullptr;
    g_state = nullptr;
}

} // namespace dbus_service
