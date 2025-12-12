#pragma once

#include "../types/enums.hpp"
#include <array>
#include <cstdint>
#include <vector>

namespace airpods::commands {

// Control command header: 04 00 04 00 09 00
constexpr std::array<uint8_t, 6> HEADER = {0x04, 0x00, 0x04, 0x00, 0x09, 0x00};

// Create a control command packet
// Format: [HEADER][identifier][data1][data2][data3][data4]
inline std::vector<uint8_t> create(uint8_t identifier, uint8_t data1 = 0x00,
                                    uint8_t data2 = 0x00, uint8_t data3 = 0x00,
                                    uint8_t data4 = 0x00) {
    return {
        HEADER[0], HEADER[1], HEADER[2], HEADER[3], HEADER[4], HEADER[5],
        identifier, data1, data2, data3, data4
    };
}

// Command identifiers
namespace ids {
    constexpr uint8_t NOISE_CONTROL = 0x0D;
    constexpr uint8_t ONE_BUD_ANC = 0x1B;
    constexpr uint8_t VOLUME_SWIPE = 0x25;
    constexpr uint8_t ADAPTIVE_VOLUME = 0x26;
    constexpr uint8_t CONVERSATIONAL_AWARENESS = 0x28;
    constexpr uint8_t HEARING_AID = 0x2C;
    constexpr uint8_t ADAPTIVE_NOISE = 0x2E;
    constexpr uint8_t HEARING_ASSIST = 0x33;
    constexpr uint8_t ALLOW_OFF_OPTION = 0x34;
}

// Noise control mode commands
namespace noise_control {
    inline std::vector<uint8_t> off() {
        return create(ids::NOISE_CONTROL, 0x01);
    }

    inline std::vector<uint8_t> anc() {
        return create(ids::NOISE_CONTROL, 0x02);
    }

    inline std::vector<uint8_t> transparency() {
        return create(ids::NOISE_CONTROL, 0x03);
    }

    inline std::vector<uint8_t> adaptive() {
        return create(ids::NOISE_CONTROL, 0x04);
    }

    inline std::vector<uint8_t> for_mode(NoiseControlMode mode) {
        switch (mode) {
            case NoiseControlMode::Off: return off();
            case NoiseControlMode::NoiseCancellation: return anc();
            case NoiseControlMode::Transparency: return transparency();
            case NoiseControlMode::Adaptive: return adaptive();
        }
        return off();
    }
}

// Conversational awareness commands
namespace conversational_awareness {
    inline std::vector<uint8_t> enable() {
        return create(ids::CONVERSATIONAL_AWARENESS, 0x01);
    }

    inline std::vector<uint8_t> disable() {
        return create(ids::CONVERSATIONAL_AWARENESS, 0x02);
    }
}

// One bud ANC mode
namespace one_bud_anc {
    inline std::vector<uint8_t> enable() {
        return create(ids::ONE_BUD_ANC, 0x01);
    }

    inline std::vector<uint8_t> disable() {
        return create(ids::ONE_BUD_ANC, 0x02);
    }
}

// Hearing aid
namespace hearing_aid {
    inline std::vector<uint8_t> enable() {
        return create(ids::HEARING_AID, 0x01, 0x01);
    }

    inline std::vector<uint8_t> disable() {
        return create(ids::HEARING_AID, 0x02, 0x02);
    }
}

// Adaptive noise level (0-100)
namespace adaptive_noise {
    inline std::vector<uint8_t> set_level(uint8_t level) {
        return create(ids::ADAPTIVE_NOISE, level);
    }
}

// Rename device
namespace rename {
    inline std::vector<uint8_t> set_name(std::string_view name) {
        // Header: 04 00 04 00 1A 00 01 [length] 00 [name bytes]
        std::vector<uint8_t> packet = {0x04, 0x00, 0x04, 0x00, 0x1A, 0x00, 0x01};
        packet.push_back(static_cast<uint8_t>(name.size()));
        packet.push_back(0x00);
        for (char c : name) {
            packet.push_back(static_cast<uint8_t>(c));
        }
        return packet;
    }
}

} // namespace airpods::commands
