#include "parse.hpp"
#include <algorithm>
#include <climits>

namespace airpods::parse {

PacketType identify_packet(std::span<const uint8_t> data) {
    using namespace packets;

    if (starts_with(data, headers::HANDSHAKE_ACK)) return PacketType::HandshakeAck;
    if (starts_with(data, headers::FEATURES_ACK)) return PacketType::FeaturesAck;
    if (starts_with(data, headers::BATTERY)) return PacketType::Battery;
    if (starts_with(data, headers::EAR_DETECTION)) return PacketType::EarDetection;
    if (starts_with(data, headers::NOISE_CONTROL)) return PacketType::NoiseControlMode;
    if (starts_with(data, headers::METADATA)) return PacketType::Metadata;
    if (starts_with(data, headers::MAGIC_KEYS)) return PacketType::MagicKeys;
    if (starts_with(data, headers::CONVERSATIONAL_AWARENESS)) return PacketType::ConversationalAwareness;
    if (starts_with(data, headers::HEARING_AID)) return PacketType::HearingAid;
    if (starts_with(data, headers::ONE_BUD_ANC)) return PacketType::OneBudAnc;

    return PacketType::Unknown;
}

std::optional<Battery> parse_battery(std::span<const uint8_t> data) {
    // Header: 04 00 04 00 04 00 [count] [components...]
    // Each component: [type] 01 [level] [status] 01
    if (!packets::starts_with(data, packets::headers::BATTERY)) {
        return std::nullopt;
    }

    if (data.size() < 7) {
        return std::nullopt;
    }

    uint8_t count = data[6];
    size_t expected_size = 7 + (5 * count);
    if (count > 4 || data.size() != expected_size) {
        return std::nullopt;
    }

    Battery battery{};
    bool first_pod_is_left = true;
    bool found_first_pod = false;

    for (uint8_t i = 0; i < count; ++i) {
        size_t offset = 7 + (5 * i);

        uint8_t type = data[offset];
        // Verify spacer bytes
        if (data[offset + 1] != 0x01 || data[offset + 4] != 0x01) {
            return std::nullopt;
        }

        uint8_t level = data[offset + 2];
        auto status = static_cast<BatteryStatus>(data[offset + 3]);

        ComponentBattery comp;
        comp.level = static_cast<int8_t>(level);
        comp.charging = (status == BatteryStatus::Charging);
        comp.available = (status != BatteryStatus::Disconnected);

        auto comp_type = static_cast<BatteryComponent>(type);

        switch (comp_type) {
            case BatteryComponent::Left:
                battery.left = comp;
                if (!found_first_pod) {
                    first_pod_is_left = true;
                    found_first_pod = true;
                }
                break;
            case BatteryComponent::Right:
                battery.right = comp;
                if (!found_first_pod) {
                    first_pod_is_left = false;
                    found_first_pod = true;
                }
                break;
            case BatteryComponent::Case:
                battery.case_ = comp;
                break;
            case BatteryComponent::Headset:
                battery.headset = comp;
                break;
        }
    }

    battery.left_is_primary = first_pod_is_left;
    return battery;
}

std::optional<EarDetection> parse_ear_detection(std::span<const uint8_t> data) {
    // Header: 04 00 04 00 06 00 [primary] [secondary]
    if (!packets::starts_with(data, packets::headers::EAR_DETECTION)) {
        return std::nullopt;
    }

    if (data.size() < 8) {
        return std::nullopt;
    }

    EarDetection detection{};
    detection.primary = static_cast<EarStatus>(data[6]);
    detection.secondary = static_cast<EarStatus>(data[7]);

    // Validate values
    if (data[6] > 0x02 || data[7] > 0x02) {
        return std::nullopt;
    }

    return detection;
}

std::optional<NoiseControlMode> parse_noise_control_mode(std::span<const uint8_t> data) {
    // Header: 04 00 04 00 09 00 0D [mode] ...
    // Mode at byte 7: 0x01=off, 0x02=anc, 0x03=transparency, 0x04=adaptive
    if (!packets::starts_with(data, packets::headers::NOISE_CONTROL)) {
        return std::nullopt;
    }

    if (data.size() < 8) {
        return std::nullopt;
    }

    // Mode value is 1-indexed in protocol, 0-indexed in enum
    uint8_t mode_value = data[7];
    if (mode_value < 1 || mode_value > 4) {
        return std::nullopt;
    }

    return static_cast<NoiseControlMode>(mode_value - 1);
}

std::optional<bool> parse_bool_state(std::span<const uint8_t> data) {
    // Control command format: [header 6 bytes][identifier][value]...
    // Value at byte 7: 0x01=enabled, 0x02=disabled
    if (data.size() < 8) {
        return std::nullopt;
    }

    switch (data[7]) {
        case 0x01: return true;
        case 0x02: return false;
        default: return std::nullopt;
    }
}

std::optional<MetadataInfo> parse_metadata(std::span<const uint8_t> data) {
    // Header: 04 00 04 00 1d [size bytes] [6 skip bytes] [null-terminated strings...]
    if (!packets::starts_with(data, packets::headers::METADATA)) {
        return std::nullopt;
    }

    // Skip header (5 bytes) + size byte (1) + reserved (6) = 12 bytes minimum before strings
    size_t pos = packets::headers::METADATA.size();
    if (data.size() < pos + 7) {
        return std::nullopt;
    }

    pos += 6;  // Skip additional header bytes

    auto extract_string = [&data, &pos]() -> std::string {
        if (pos >= data.size()) return {};

        size_t start = pos;
        while (pos < data.size() && data[pos] != 0) {
            ++pos;
        }

        std::string result(reinterpret_cast<const char*>(data.data() + start), pos - start);

        if (pos < data.size()) {
            ++pos;  // Skip null terminator
        }

        return result;
    };

    MetadataInfo info;
    info.device_name = extract_string();
    info.model_number = extract_string();
    info.manufacturer = extract_string();

    return info;
}

std::optional<MagicKeys> parse_magic_keys(std::span<const uint8_t> data) {
    // Header: 04 00 04 00 31 00 02 [TLV blocks...]
    // TLV: [type] [len_hi] [len_lo] [reserved] [data...]
    // Type 0x01 = IRK (16 bytes), Type 0x04 = EncKey (16 bytes)
    if (!packets::starts_with(data, packets::headers::MAGIC_KEYS)) {
        return std::nullopt;
    }

    if (data.size() < 47) {  // Header + 2 TLV blocks with 16-byte values
        return std::nullopt;
    }

    size_t idx = packets::headers::MAGIC_KEYS.size();

    MagicKeys keys{};

    // First TLV: IRK
    if (data[idx] != 0x01) return std::nullopt;
    idx += 1;

    uint16_t len1 = (static_cast<uint16_t>(data[idx]) << 8) | data[idx + 1];
    if (len1 != 16) return std::nullopt;
    idx += 3;  // Skip length (2) + reserved (1)

    std::copy(data.begin() + idx, data.begin() + idx + 16, keys.irk.begin());
    idx += 16;

    // Second TLV: EncKey
    if (data[idx] != 0x04) return std::nullopt;
    idx += 1;

    uint16_t len2 = (static_cast<uint16_t>(data[idx]) << 8) | data[idx + 1];
    if (len2 != 16) return std::nullopt;
    idx += 3;

    std::copy(data.begin() + idx, data.begin() + idx + 16, keys.enc_key.begin());

    return keys;
}

std::optional<Battery> parse_encrypted_battery(std::span<const uint8_t, 16> decrypted,
                                                bool left_is_primary,
                                                bool pod_in_case,
                                                bool is_headset) {
    // Decrypted packet format:
    // Byte 0: unknown
    // Byte 1: primary battery (bit 7 = charging, bits 0-6 = level 0-127, 127 = unknown)
    // Byte 2: secondary battery
    // Byte 3: case battery

    auto format_battery = [](uint8_t byte) -> std::pair<bool, int8_t> {
        bool charging = (byte & 0x80) != 0;
        int8_t level = byte & 0x7F;
        if (level == 127) {
            level = -1;  // Unknown/unavailable
        }
        return {charging, level};
    };

    Battery battery{};

    int primary_idx = left_is_primary ? 1 : 2;
    int secondary_idx = left_is_primary ? 2 : 1;

    auto [left_charging, left_level] = format_battery(decrypted[primary_idx]);
    auto [right_charging, right_level] = format_battery(decrypted[secondary_idx]);
    auto [case_charging, case_level] = format_battery(decrypted[3]);

    if (is_headset) {
        // AirPods Max: find first available battery
        std::array<std::pair<bool, int8_t>, 3> batteries = {
            format_battery(decrypted[1]),
            format_battery(decrypted[2]),
            format_battery(decrypted[3])
        };

        for (const auto& [charging, level] : batteries) {
            if (level != -1) {
                battery.headset.level = level;
                battery.headset.charging = charging;
                battery.headset.available = true;
                break;
            }
        }
    } else {
        battery.left.level = left_level;
        battery.left.charging = left_charging;
        battery.left.available = (left_level != -1);

        battery.right.level = right_level;
        battery.right.charging = right_charging;
        battery.right.available = (right_level != -1);

        if (pod_in_case) {
            battery.case_.level = case_level;
            battery.case_.charging = case_charging;
            battery.case_.available = (case_level != -1);
        }
    }

    battery.left_is_primary = left_is_primary;
    return battery;
}

} // namespace airpods::parse
