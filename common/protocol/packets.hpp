#pragma once

#include <array>
#include <cstdint>
#include <span>
#include <vector>

namespace airpods::packets {

// Helper to create packet from hex string literal
template<size_t N>
constexpr std::array<uint8_t, (N - 1) / 2> from_hex(const char (&hex)[N]) {
    std::array<uint8_t, (N - 1) / 2> result{};
    for (size_t i = 0; i < result.size(); ++i) {
        auto hex_to_nibble = [](char c) -> uint8_t {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            if (c >= 'A' && c <= 'F') return c - 'A' + 10;
            return 0;
        };
        result[i] = (hex_to_nibble(hex[i * 2]) << 4) | hex_to_nibble(hex[i * 2 + 1]);
    }
    return result;
}

// Connection packets
namespace connection {
    // Initial handshake: 00 00 04 00 01 00 02 00 00 00 00 00 00 00 00 00
    constexpr auto HANDSHAKE = from_hex("00000400010002000000000000000000");

    // Set specific features: 04 00 04 00 4d 00 d7 00 00 00 00 00 00 00
    constexpr auto SET_FEATURES = from_hex("040004004d00d700000000000000");

    // Request notifications: 04 00 04 00 0f 00 ff ff ff ff ff
    constexpr auto REQUEST_NOTIFICATIONS = from_hex("040004000f00ffffffffff");

    // AirPods disconnected indicator
    constexpr auto DISCONNECTED = from_hex("00010000");
}

// Packet headers for parsing
namespace headers {
    // Control command header: 04 00 04 00 09 00
    constexpr auto CONTROL = from_hex("040004000900");

    // Noise control: 04 00 04 00 09 00 0D
    constexpr auto NOISE_CONTROL = from_hex("0400040009000D");

    // Battery status: 04 00 04 00 04 00
    constexpr auto BATTERY = from_hex("040004000400");

    // Ear detection: 04 00 04 00 06 00
    constexpr auto EAR_DETECTION = from_hex("040004000600");

    // Metadata: 04 00 04 00 1d
    constexpr auto METADATA = from_hex("040004001d");

    // Handshake ack: 01 00 04 00
    constexpr auto HANDSHAKE_ACK = from_hex("01000400");

    // Features ack: 04 00 04 00 2b 00
    constexpr auto FEATURES_ACK = from_hex("040004002b00");

    // Magic cloud keys: 04 00 04 00 31 00 02
    constexpr auto MAGIC_KEYS = from_hex("04000400310002");

    // Conversational awareness: 04 00 04 00 09 00 28
    constexpr auto CONVERSATIONAL_AWARENESS = from_hex("04000400090028");

    // Hearing aid: 04 00 04 00 09 00 2C
    constexpr auto HEARING_AID = from_hex("0400040009002C");

    // One bud ANC: 04 00 04 00 09 00 1B
    constexpr auto ONE_BUD_ANC = from_hex("0400040009001B");
}

// Magic pairing
namespace magic_pairing {
    constexpr auto REQUEST_KEYS = from_hex("0400040030000500");
}

// Helper to check if data starts with a header
template<size_t N>
inline bool starts_with(std::span<const uint8_t> data, const std::array<uint8_t, N>& header) {
    if (data.size() < N) return false;
    for (size_t i = 0; i < N; ++i) {
        if (data[i] != header[i]) return false;
    }
    return true;
}

} // namespace airpods::packets
