#pragma once

#include <cstdint>

namespace airpods {

enum class BatteryStatus : uint8_t {
    Charging = 0x01,
    Discharging = 0x02,
    Disconnected = 0x04,
};

enum class BatteryComponent : uint8_t {
    Headset = 0x01,  // AirPods Max
    Right = 0x02,
    Left = 0x04,
    Case = 0x08,
};

struct ComponentBattery {
    int8_t level = -1;  // 0-100, or -1 if unavailable
    bool charging = false;
    bool available = false;
};

struct Battery {
    ComponentBattery left{};
    ComponentBattery right{};
    ComponentBattery case_{};
    ComponentBattery headset{};  // For AirPods Max

    // Which pod is primary (first in packet order)
    bool left_is_primary = true;
};

} // namespace airpods
