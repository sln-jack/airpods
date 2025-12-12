#include "bluez.hpp"
#include <algorithm>
#include <cstring>
#include <iostream>

namespace bluez {

// Apple manufacturer ID
constexpr uint16_t APPLE_MANUFACTURER_ID = 0x004C;  // 76 decimal

// Helper to call a method with no arguments and no return
static bool call_method_void(DBusConnection* conn, const char* dest, const char* path,
                              const char* iface, const char* method) {
    DBusMessage* msg = dbus_message_new_method_call(dest, path, iface, method);
    if (!msg) return false;

    DBusError err;
    dbus_error_init(&err);

    DBusMessage* reply = dbus_connection_send_with_reply_and_block(conn, msg, 5000, &err);
    dbus_message_unref(msg);

    if (dbus_error_is_set(&err)) {
        // "Already" errors are OK (already connected, already discovering, etc)
        if (strstr(err.message, "Already") || strstr(err.message, "already")) {
            dbus_error_free(&err);
            return true;
        }
        std::cerr << "bluez: " << method << " failed: " << err.message << std::endl;
        dbus_error_free(&err);
        return false;
    }

    if (reply) dbus_message_unref(reply);
    return true;
}

// Helper to get a string property
static std::string get_string_property(DBusConnection* conn, const char* path,
                                        const char* iface, const char* prop) {
    DBusMessage* msg = dbus_message_new_method_call("org.bluez", path,
        "org.freedesktop.DBus.Properties", "Get");
    if (!msg) return "";

    dbus_message_append_args(msg, DBUS_TYPE_STRING, &iface,
                             DBUS_TYPE_STRING, &prop, DBUS_TYPE_INVALID);

    DBusError err;
    dbus_error_init(&err);
    DBusMessage* reply = dbus_connection_send_with_reply_and_block(conn, msg, 2000, &err);
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

// Helper to get a bool property
static bool get_bool_property(DBusConnection* conn, const char* path,
                               const char* iface, const char* prop) {
    DBusMessage* msg = dbus_message_new_method_call("org.bluez", path,
        "org.freedesktop.DBus.Properties", "Get");
    if (!msg) return false;

    dbus_message_append_args(msg, DBUS_TYPE_STRING, &iface,
                             DBUS_TYPE_STRING, &prop, DBUS_TYPE_INVALID);

    DBusError err;
    dbus_error_init(&err);
    DBusMessage* reply = dbus_connection_send_with_reply_and_block(conn, msg, 2000, &err);
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

bool is_airpods(DBusMessageIter* uuids_iter) {
    if (dbus_message_iter_get_arg_type(uuids_iter) != DBUS_TYPE_ARRAY) {
        return false;
    }

    DBusMessageIter array_iter;
    dbus_message_iter_recurse(uuids_iter, &array_iter);

    while (dbus_message_iter_get_arg_type(&array_iter) == DBUS_TYPE_STRING) {
        const char* uuid;
        dbus_message_iter_get_basic(&array_iter, &uuid);
        if (strcmp(uuid, AIRPODS_UUID) == 0) {
            return true;
        }
        dbus_message_iter_next(&array_iter);
    }
    return false;
}

bool is_airpods_name(const std::string& name) {
    // Check if name contains "AirPods" (case-insensitive would be better but this suffices)
    return name.find("AirPods") != std::string::npos ||
           name.find("airpods") != std::string::npos;
}

// Check if manufacturer data indicates AirPods (Apple 0x004C with 0x07 prefix)
// Returns true if this is an AirPods device (paired or in pairing mode)
static bool check_apple_manufacturer_data(DBusMessageIter* mfr_data_iter) {
    // ManufacturerData is a{qv} - dict of uint16 -> variant(array of bytes)
    if (dbus_message_iter_get_arg_type(mfr_data_iter) != DBUS_TYPE_ARRAY) {
        return false;
    }

    DBusMessageIter dict;
    dbus_message_iter_recurse(mfr_data_iter, &dict);

    while (dbus_message_iter_get_arg_type(&dict) == DBUS_TYPE_DICT_ENTRY) {
        DBusMessageIter entry;
        dbus_message_iter_recurse(&dict, &entry);

        // Get manufacturer ID (uint16)
        if (dbus_message_iter_get_arg_type(&entry) != DBUS_TYPE_UINT16) {
            dbus_message_iter_next(&dict);
            continue;
        }

        uint16_t mfr_id;
        dbus_message_iter_get_basic(&entry, &mfr_id);

        if (mfr_id == APPLE_MANUFACTURER_ID) {
            dbus_message_iter_next(&entry);
            if (dbus_message_iter_get_arg_type(&entry) != DBUS_TYPE_VARIANT) {
                dbus_message_iter_next(&dict);
                continue;
            }

            DBusMessageIter variant;
            dbus_message_iter_recurse(&entry, &variant);

            if (dbus_message_iter_get_arg_type(&variant) != DBUS_TYPE_ARRAY) {
                dbus_message_iter_next(&dict);
                continue;
            }

            DBusMessageIter bytes;
            dbus_message_iter_recurse(&variant, &bytes);

            // Get first byte - should be 0x07 for Proximity Pairing Message
            if (dbus_message_iter_get_arg_type(&bytes) == DBUS_TYPE_BYTE) {
                uint8_t first_byte;
                dbus_message_iter_get_basic(&bytes, &first_byte);
                if (first_byte == 0x07) {
                    return true;  // This is AirPods!
                }
            }
        }
        dbus_message_iter_next(&dict);
    }
    return false;
}

// Check device for AirPods via ManufacturerData property
static bool has_apple_manufacturer_data(DBusConnection* conn, const char* path) {
    DBusMessage* msg = dbus_message_new_method_call("org.bluez", path,
        "org.freedesktop.DBus.Properties", "Get");
    if (!msg) return false;

    const char* iface = "org.bluez.Device1";
    const char* prop = "ManufacturerData";
    dbus_message_append_args(msg, DBUS_TYPE_STRING, &iface,
                             DBUS_TYPE_STRING, &prop, DBUS_TYPE_INVALID);

    DBusError err;
    dbus_error_init(&err);
    DBusMessage* reply = dbus_connection_send_with_reply_and_block(conn, msg, 2000, &err);
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
            result = check_apple_manufacturer_data(&variant);
        }
        dbus_message_unref(reply);
    }
    return result;
}

// Check if device path is AirPods by checking:
// 1. UUIDs (works for paired devices)
// 2. ManufacturerData (works for all devices including unpaired)
// 3. Name (fallback)
static bool is_airpods_device(DBusConnection* conn, const char* path) {
    // First try UUIDs (most reliable for paired devices)
    DBusMessage* msg = dbus_message_new_method_call("org.bluez", path,
        "org.freedesktop.DBus.Properties", "Get");
    if (!msg) return false;

    const char* iface = "org.bluez.Device1";
    const char* prop = "UUIDs";
    dbus_message_append_args(msg, DBUS_TYPE_STRING, &iface,
                             DBUS_TYPE_STRING, &prop, DBUS_TYPE_INVALID);

    DBusError err;
    dbus_error_init(&err);
    DBusMessage* reply = dbus_connection_send_with_reply_and_block(conn, msg, 2000, &err);
    dbus_message_unref(msg);

    if (!dbus_error_is_set(&err) && reply) {
        DBusMessageIter iter, variant;
        if (dbus_message_iter_init(reply, &iter) &&
            dbus_message_iter_get_arg_type(&iter) == DBUS_TYPE_VARIANT) {
            dbus_message_iter_recurse(&iter, &variant);
            if (is_airpods(&variant)) {
                dbus_message_unref(reply);
                return true;
            }
        }
        dbus_message_unref(reply);
    }
    if (dbus_error_is_set(&err)) {
        dbus_error_free(&err);
    }

    // Try ManufacturerData (works for unpaired devices in discovery)
    if (has_apple_manufacturer_data(conn, path)) {
        return true;
    }

    // Fallback: check name
    std::string name = get_string_property(conn, path, "org.bluez.Device1", "Name");
    return is_airpods_name(name);
}

std::optional<std::string> get_adapter_path(DBusConnection* conn) {
    DBusMessage* msg = dbus_message_new_method_call("org.bluez", "/",
        "org.freedesktop.DBus.ObjectManager", "GetManagedObjects");
    if (!msg) return std::nullopt;

    DBusError err;
    dbus_error_init(&err);
    DBusMessage* reply = dbus_connection_send_with_reply_and_block(conn, msg, 5000, &err);
    dbus_message_unref(msg);

    if (dbus_error_is_set(&err)) {
        std::cerr << "bluez: GetManagedObjects failed: " << err.message << std::endl;
        dbus_error_free(&err);
        return std::nullopt;
    }

    std::optional<std::string> result;

    if (reply) {
        DBusMessageIter iter, dict;
        if (dbus_message_iter_init(reply, &iter) &&
            dbus_message_iter_get_arg_type(&iter) == DBUS_TYPE_ARRAY) {

            dbus_message_iter_recurse(&iter, &dict);

            while (dbus_message_iter_get_arg_type(&dict) == DBUS_TYPE_DICT_ENTRY) {
                DBusMessageIter entry, ifaces;
                dbus_message_iter_recurse(&dict, &entry);

                const char* obj_path;
                dbus_message_iter_get_basic(&entry, &obj_path);
                dbus_message_iter_next(&entry);

                // Check interfaces
                if (dbus_message_iter_get_arg_type(&entry) == DBUS_TYPE_ARRAY) {
                    dbus_message_iter_recurse(&entry, &ifaces);

                    while (dbus_message_iter_get_arg_type(&ifaces) == DBUS_TYPE_DICT_ENTRY) {
                        DBusMessageIter iface_entry;
                        dbus_message_iter_recurse(&ifaces, &iface_entry);

                        const char* iface_name;
                        dbus_message_iter_get_basic(&iface_entry, &iface_name);

                        if (strcmp(iface_name, "org.bluez.Adapter1") == 0) {
                            result = obj_path;
                            break;
                        }
                        dbus_message_iter_next(&ifaces);
                    }
                }

                if (result) break;
                dbus_message_iter_next(&dict);
            }
        }
        dbus_message_unref(reply);
    }

    return result;
}

// Helper to get device info from path
static DeviceInfo get_device_info(DBusConnection* conn, const char* obj_path) {
    DeviceInfo info;
    info.path = obj_path;
    info.address = get_string_property(conn, obj_path, "org.bluez.Device1", "Address");
    info.name = get_string_property(conn, obj_path, "org.bluez.Device1", "Name");
    info.connected = get_bool_property(conn, obj_path, "org.bluez.Device1", "Connected");
    info.paired = get_bool_property(conn, obj_path, "org.bluez.Device1", "Paired");
    return info;
}

std::vector<DeviceInfo> find_paired_airpods(DBusConnection* conn) {
    std::vector<DeviceInfo> result;

    DBusMessage* msg = dbus_message_new_method_call("org.bluez", "/",
        "org.freedesktop.DBus.ObjectManager", "GetManagedObjects");
    if (!msg) return result;

    DBusError err;
    dbus_error_init(&err);
    DBusMessage* reply = dbus_connection_send_with_reply_and_block(conn, msg, 5000, &err);
    dbus_message_unref(msg);

    if (dbus_error_is_set(&err)) {
        dbus_error_free(&err);
        return result;
    }

    if (reply) {
        DBusMessageIter iter, dict;
        if (dbus_message_iter_init(reply, &iter) &&
            dbus_message_iter_get_arg_type(&iter) == DBUS_TYPE_ARRAY) {

            dbus_message_iter_recurse(&iter, &dict);

            while (dbus_message_iter_get_arg_type(&dict) == DBUS_TYPE_DICT_ENTRY) {
                DBusMessageIter entry;
                dbus_message_iter_recurse(&dict, &entry);

                const char* obj_path;
                dbus_message_iter_get_basic(&entry, &obj_path);

                // Check if it's a device and if it's AirPods
                if (strstr(obj_path, "/dev_") && is_airpods_device(conn, obj_path)) {
                    auto info = get_device_info(conn, obj_path);
                    if (info.paired) {
                        result.push_back(std::move(info));
                    }
                }

                dbus_message_iter_next(&dict);
            }
        }
        dbus_message_unref(reply);
    }

    return result;
}

std::vector<DeviceInfo> find_unpaired_airpods(DBusConnection* conn) {
    std::vector<DeviceInfo> result;

    DBusMessage* msg = dbus_message_new_method_call("org.bluez", "/",
        "org.freedesktop.DBus.ObjectManager", "GetManagedObjects");
    if (!msg) return result;

    DBusError err;
    dbus_error_init(&err);
    DBusMessage* reply = dbus_connection_send_with_reply_and_block(conn, msg, 5000, &err);
    dbus_message_unref(msg);

    if (dbus_error_is_set(&err)) {
        dbus_error_free(&err);
        return result;
    }

    if (reply) {
        DBusMessageIter iter, dict;
        if (dbus_message_iter_init(reply, &iter) &&
            dbus_message_iter_get_arg_type(&iter) == DBUS_TYPE_ARRAY) {

            dbus_message_iter_recurse(&iter, &dict);

            while (dbus_message_iter_get_arg_type(&dict) == DBUS_TYPE_DICT_ENTRY) {
                DBusMessageIter entry;
                dbus_message_iter_recurse(&dict, &entry);

                const char* obj_path;
                dbus_message_iter_get_basic(&entry, &obj_path);

                // Check if it's a device and if it's AirPods
                if (strstr(obj_path, "/dev_") && is_airpods_device(conn, obj_path)) {
                    auto info = get_device_info(conn, obj_path);
                    if (!info.paired) {
                        result.push_back(std::move(info));
                    }
                }

                dbus_message_iter_next(&dict);
            }
        }
        dbus_message_unref(reply);
    }

    return result;
}

std::optional<DeviceInfo> find_connected_airpods(DBusConnection* conn) {
    auto devices = find_paired_airpods(conn);
    for (auto& dev : devices) {
        if (dev.connected) {
            return std::move(dev);
        }
    }
    return std::nullopt;
}

bool start_discovery(DBusConnection* conn) {
    auto adapter = get_adapter_path(conn);
    if (!adapter) {
        std::cerr << "bluez: no adapter found" << std::endl;
        return false;
    }

    return call_method_void(conn, "org.bluez", adapter->c_str(),
                           "org.bluez.Adapter1", "StartDiscovery");
}

void stop_discovery(DBusConnection* conn) {
    auto adapter = get_adapter_path(conn);
    if (!adapter) return;

    call_method_void(conn, "org.bluez", adapter->c_str(),
                    "org.bluez.Adapter1", "StopDiscovery");
}

bool connect_device(DBusConnection* conn, const std::string& device_path) {
    return call_method_void(conn, "org.bluez", device_path.c_str(),
                           "org.bluez.Device1", "Connect");
}

bool disconnect_device(DBusConnection* conn, const std::string& device_path) {
    return call_method_void(conn, "org.bluez", device_path.c_str(),
                           "org.bluez.Device1", "Disconnect");
}

bool pair_device(DBusConnection* conn, const std::string& device_path) {
    return call_method_void(conn, "org.bluez", device_path.c_str(),
                           "org.bluez.Device1", "Pair");
}

bool trust_device(DBusConnection* conn, const std::string& device_path) {
    // Set Trusted property to true
    DBusMessage* msg = dbus_message_new_method_call("org.bluez", device_path.c_str(),
        "org.freedesktop.DBus.Properties", "Set");
    if (!msg) return false;

    const char* iface = "org.bluez.Device1";
    const char* prop = "Trusted";
    dbus_message_append_args(msg, DBUS_TYPE_STRING, &iface,
                             DBUS_TYPE_STRING, &prop, DBUS_TYPE_INVALID);

    // Append variant(bool true)
    DBusMessageIter iter, variant;
    dbus_message_iter_init_append(msg, &iter);
    dbus_message_iter_open_container(&iter, DBUS_TYPE_VARIANT, "b", &variant);
    dbus_bool_t val = TRUE;
    dbus_message_iter_append_basic(&variant, DBUS_TYPE_BOOLEAN, &val);
    dbus_message_iter_close_container(&iter, &variant);

    DBusError err;
    dbus_error_init(&err);
    DBusMessage* reply = dbus_connection_send_with_reply_and_block(conn, msg, 2000, &err);
    dbus_message_unref(msg);

    if (dbus_error_is_set(&err)) {
        std::cerr << "bluez: trust_device failed: " << err.message << std::endl;
        dbus_error_free(&err);
        return false;
    }

    if (reply) dbus_message_unref(reply);
    std::cout << "bluez: device trusted" << std::endl;
    return true;
}

void setup_signal_handlers(DBusConnection* conn, const Callbacks* callbacks) {
    (void)callbacks;  // Stored by caller

    DBusError err;
    dbus_error_init(&err);

    // Subscribe to InterfacesAdded (new devices discovered)
    dbus_bus_add_match(conn,
        "type='signal',sender='org.bluez',interface='org.freedesktop.DBus.ObjectManager',member='InterfacesAdded'",
        &err);
    if (dbus_error_is_set(&err)) {
        std::cerr << "bluez: failed to add InterfacesAdded match: " << err.message << std::endl;
        dbus_error_free(&err);
    }

    // Subscribe to PropertiesChanged (Connected state changes)
    dbus_bus_add_match(conn,
        "type='signal',sender='org.bluez',interface='org.freedesktop.DBus.Properties',member='PropertiesChanged'",
        &err);
    if (dbus_error_is_set(&err)) {
        std::cerr << "bluez: failed to add PropertiesChanged match: " << err.message << std::endl;
        dbus_error_free(&err);
    }

    dbus_connection_flush(conn);
}

// Check if interfaces dict contains org.bluez.Device1 with AirPods indicators
// Checks: UUIDs, ManufacturerData, and Name
static bool check_interfaces_for_airpods(DBusMessageIter* ifaces_iter) {
    while (dbus_message_iter_get_arg_type(ifaces_iter) == DBUS_TYPE_DICT_ENTRY) {
        DBusMessageIter entry, props;
        dbus_message_iter_recurse(ifaces_iter, &entry);

        const char* iface_name;
        dbus_message_iter_get_basic(&entry, &iface_name);

        if (strcmp(iface_name, "org.bluez.Device1") == 0) {
            dbus_message_iter_next(&entry);
            if (dbus_message_iter_get_arg_type(&entry) == DBUS_TYPE_ARRAY) {
                dbus_message_iter_recurse(&entry, &props);

                bool found_by_uuid = false;
                bool found_by_mfr_data = false;
                bool found_by_name = false;

                // Look through properties
                while (dbus_message_iter_get_arg_type(&props) == DBUS_TYPE_DICT_ENTRY) {
                    DBusMessageIter prop_entry, variant;
                    dbus_message_iter_recurse(&props, &prop_entry);

                    const char* prop_name;
                    dbus_message_iter_get_basic(&prop_entry, &prop_name);
                    dbus_message_iter_next(&prop_entry);

                    if (dbus_message_iter_get_arg_type(&prop_entry) == DBUS_TYPE_VARIANT) {
                        dbus_message_iter_recurse(&prop_entry, &variant);

                        if (strcmp(prop_name, "UUIDs") == 0) {
                            if (is_airpods(&variant)) {
                                found_by_uuid = true;
                            }
                        } else if (strcmp(prop_name, "ManufacturerData") == 0) {
                            if (check_apple_manufacturer_data(&variant)) {
                                found_by_mfr_data = true;
                            }
                        } else if (strcmp(prop_name, "Name") == 0) {
                            if (dbus_message_iter_get_arg_type(&variant) == DBUS_TYPE_STRING) {
                                const char* name;
                                dbus_message_iter_get_basic(&variant, &name);
                                if (is_airpods_name(name)) {
                                    found_by_name = true;
                                }
                            }
                        }
                    }
                    dbus_message_iter_next(&props);
                }

                if (found_by_uuid || found_by_mfr_data || found_by_name) {
                    return true;
                }
            }
        }
        dbus_message_iter_next(ifaces_iter);
    }
    return false;
}

std::string get_device_path(const std::string& mac_address) {
    std::string result = mac_address;
    std::replace(result.begin(), result.end(), ':', '_');
    return "/org/bluez/hci0/dev_" + result;
}

bool activate_a2dp(DBusConnection* conn, const std::string& mac_address) {
    constexpr const char* A2DP_SINK_UUID = "0000110b-0000-1000-8000-00805f9b34fb";

    std::string device_path = get_device_path(mac_address);

    // First ensure device is connected via BlueZ
    DBusMessage* msg = dbus_message_new_method_call("org.bluez", device_path.c_str(),
        "org.bluez.Device1", "Connect");
    if (!msg) return false;

    DBusError err;
    dbus_error_init(&err);
    DBusMessage* reply = dbus_connection_send_with_reply_and_block(conn, msg, 10000, &err);
    dbus_message_unref(msg);

    if (dbus_error_is_set(&err)) {
        // "Already Connected" or "busy" are OK
        if (!strstr(err.message, "Already") && !strstr(err.message, "already") &&
            !strstr(err.message, "busy") && !strstr(err.message, "Busy")) {
            std::cerr << "bluez: Connect failed: " << err.message << std::endl;
            dbus_error_free(&err);
            return false;
        }
        dbus_error_free(&err);
    }
    if (reply) dbus_message_unref(reply);

    // Now connect specifically to A2DP Sink profile
    msg = dbus_message_new_method_call("org.bluez", device_path.c_str(),
        "org.bluez.Device1", "ConnectProfile");
    if (!msg) return false;

    dbus_message_append_args(msg, DBUS_TYPE_STRING, &A2DP_SINK_UUID, DBUS_TYPE_INVALID);

    dbus_error_init(&err);
    reply = dbus_connection_send_with_reply_and_block(conn, msg, 10000, &err);
    dbus_message_unref(msg);

    if (dbus_error_is_set(&err)) {
        // "Already Connected" is OK
        if (!strstr(err.message, "Already") && !strstr(err.message, "already")) {
            std::cerr << "bluez: ConnectProfile A2DP failed: " << err.message << std::endl;
            dbus_error_free(&err);
            return false;
        }
        dbus_error_free(&err);
    }
    if (reply) dbus_message_unref(reply);

    std::cout << "bluez: activated A2DP profile for " << mac_address << std::endl;
    return true;
}

bool handle_signal(DBusConnection* conn, DBusMessage* msg, const Callbacks* callbacks) {
    if (!callbacks) return false;

    const char* iface = dbus_message_get_interface(msg);
    const char* member = dbus_message_get_member(msg);

    if (!iface || !member) return false;

    // Handle InterfacesAdded - new device discovered
    if (strcmp(iface, "org.freedesktop.DBus.ObjectManager") == 0 &&
        strcmp(member, "InterfacesAdded") == 0) {

        DBusMessageIter iter;
        if (!dbus_message_iter_init(msg, &iter)) return false;

        // First arg: object path
        if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_OBJECT_PATH) return false;
        const char* obj_path;
        dbus_message_iter_get_basic(&iter, &obj_path);

        // Only care about devices
        if (!strstr(obj_path, "/dev_")) return false;

        // Second arg: interfaces dict
        dbus_message_iter_next(&iter);
        if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_ARRAY) return false;

        DBusMessageIter ifaces;
        dbus_message_iter_recurse(&iter, &ifaces);

        if (check_interfaces_for_airpods(&ifaces)) {
            std::cout << "bluez: discovered AirPods at " << obj_path << std::endl;

            if (callbacks->on_airpods_found) {
                auto info = get_device_info(conn, obj_path);
                callbacks->on_airpods_found(info);
            }
        }
        return true;
    }

    // Handle PropertiesChanged - connection state
    if (strcmp(iface, "org.freedesktop.DBus.Properties") == 0 &&
        strcmp(member, "PropertiesChanged") == 0) {

        const char* obj_path = dbus_message_get_path(msg);
        if (!obj_path || !strstr(obj_path, "/dev_")) return false;

        DBusMessageIter iter;
        if (!dbus_message_iter_init(msg, &iter)) return false;

        // First arg: interface name
        if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_STRING) return false;
        const char* changed_iface;
        dbus_message_iter_get_basic(&iter, &changed_iface);

        if (strcmp(changed_iface, "org.bluez.Device1") != 0) return false;

        // Second arg: changed properties dict
        dbus_message_iter_next(&iter);
        if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_ARRAY) return false;

        DBusMessageIter props;
        dbus_message_iter_recurse(&iter, &props);

        while (dbus_message_iter_get_arg_type(&props) == DBUS_TYPE_DICT_ENTRY) {
            DBusMessageIter prop_entry, variant;
            dbus_message_iter_recurse(&props, &prop_entry);

            const char* prop_name;
            dbus_message_iter_get_basic(&prop_entry, &prop_name);

            if (strcmp(prop_name, "Connected") == 0) {
                dbus_message_iter_next(&prop_entry);
                if (dbus_message_iter_get_arg_type(&prop_entry) == DBUS_TYPE_VARIANT) {
                    dbus_message_iter_recurse(&prop_entry, &variant);
                    if (dbus_message_iter_get_arg_type(&variant) == DBUS_TYPE_BOOLEAN) {
                        dbus_bool_t connected;
                        dbus_message_iter_get_basic(&variant, &connected);

                        // Check if it's AirPods
                        if (is_airpods_device(conn, obj_path)) {
                            std::string addr = get_string_property(conn, obj_path, "org.bluez.Device1", "Address");
                            if (connected) {
                                std::cout << "bluez: AirPods connected: " << addr << std::endl;
                                if (callbacks->on_device_connected) {
                                    callbacks->on_device_connected(addr);
                                }
                            } else {
                                std::cout << "bluez: AirPods disconnected: " << addr << std::endl;
                                if (callbacks->on_device_disconnected) {
                                    callbacks->on_device_disconnected(addr);
                                }
                            }
                        }
                    }
                }
            }
            dbus_message_iter_next(&props);
        }
        return true;
    }

    return false;
}

} // namespace bluez
