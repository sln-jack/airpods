#pragma once

#include "enums.hpp"
#include "battery.hpp"
#include "ear_detection.hpp"
#include <string>
#include <array>

namespace airpods {

struct DeviceState {
    // Connection
    bool connected = false;
    std::string mac_address;

    // Identity
    std::string device_name;
    std::string model_number;
    Model model = Model::Unknown;

    // State
    NoiseControlMode noise_control_mode = NoiseControlMode::Off;
    Battery battery{};
    EarDetection ear_detection{};

    // Magic pairing keys (16 bytes each)
    std::array<uint8_t, 16> irk{};
    std::array<uint8_t, 16> enc_key{};
    bool has_magic_keys = false;
};

} // namespace airpods
