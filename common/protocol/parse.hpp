#pragma once

#include "../types/battery.hpp"
#include "../types/ear_detection.hpp"
#include "../types/enums.hpp"
#include "packets.hpp"
#include <array>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>

namespace airpods::parse {

// Identify packet type
enum class PacketType {
    Unknown,
    HandshakeAck,
    FeaturesAck,
    Battery,
    EarDetection,
    NoiseControlMode,
    Metadata,
    MagicKeys,
    ConversationalAwareness,
    HearingAid,
    OneBudAnc,
};

PacketType identify_packet(std::span<const uint8_t> data);

// Parse battery status packet
// Returns nullopt if packet is invalid
std::optional<Battery> parse_battery(std::span<const uint8_t> data);

// Parse ear detection packet
std::optional<EarDetection> parse_ear_detection(std::span<const uint8_t> data);

// Parse noise control mode from packet
std::optional<NoiseControlMode> parse_noise_control_mode(std::span<const uint8_t> data);

// Parse boolean state from control command (byte 7: 0x01=enabled, 0x02=disabled)
std::optional<bool> parse_bool_state(std::span<const uint8_t> data);

// Parse metadata packet - extracts device name, model number, manufacturer
struct MetadataInfo {
    std::string device_name;
    std::string model_number;
    std::string manufacturer;
};
std::optional<MetadataInfo> parse_metadata(std::span<const uint8_t> data);

// Parse magic cloud keys packet
struct MagicKeys {
    std::array<uint8_t, 16> irk;
    std::array<uint8_t, 16> enc_key;
};
std::optional<MagicKeys> parse_magic_keys(std::span<const uint8_t> data);

// Parse encrypted BLE battery data (from advertisement)
std::optional<Battery> parse_encrypted_battery(std::span<const uint8_t, 16> decrypted,
                                                bool left_is_primary,
                                                bool pod_in_case,
                                                bool is_headset);

} // namespace airpods::parse
