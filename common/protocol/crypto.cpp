#include "crypto.hpp"
#include <openssl/aes.h>
#include <algorithm>
#include <charconv>
#include <cstring>

namespace airpods::crypto {

std::array<uint8_t, 16> aes_encrypt(std::span<const uint8_t, 16> key,
                                     std::span<const uint8_t, 16> data) {
    // Bluetooth Core Spec requires reversed key and data
    std::array<uint8_t, 16> reversed_key;
    std::array<uint8_t, 16> reversed_data;

    std::reverse_copy(key.begin(), key.end(), reversed_key.begin());
    std::reverse_copy(data.begin(), data.end(), reversed_data.begin());

    AES_KEY aes_key;
    if (AES_set_encrypt_key(reversed_key.data(), 128, &aes_key) != 0) {
        return {};
    }

    std::array<uint8_t, 16> output;
    AES_encrypt(reversed_data.data(), output.data(), &aes_key);

    // Reverse output
    std::array<uint8_t, 16> result;
    std::reverse_copy(output.begin(), output.end(), result.begin());

    return result;
}

std::array<uint8_t, 3> address_hash(std::span<const uint8_t, 16> irk,
                                     std::span<const uint8_t, 3> prand) {
    // Pad prand to 16 bytes (prand in lower 3 bytes, rest zeros)
    std::array<uint8_t, 16> padded{};
    std::copy(prand.begin(), prand.end(), padded.begin());

    auto encrypted = aes_encrypt(irk, padded);

    // Return first 3 bytes as hash
    std::array<uint8_t, 3> hash;
    std::copy_n(encrypted.begin(), 3, hash.begin());
    return hash;
}

std::optional<std::array<uint8_t, 6>> parse_mac_address(std::string_view address) {
    std::array<uint8_t, 6> result{};

    // Expect format: AA:BB:CC:DD:EE:FF
    if (address.size() != 17) {
        return std::nullopt;
    }

    size_t byte_idx = 0;
    for (size_t i = 0; i < address.size() && byte_idx < 6; i += 3) {
        auto part = address.substr(i, 2);
        uint8_t value;
        auto [ptr, ec] = std::from_chars(part.data(), part.data() + part.size(), value, 16);
        if (ec != std::errc{}) {
            return std::nullopt;
        }
        result[byte_idx++] = value;
    }

    return result;
}

bool verify_rpa(std::string_view address, std::span<const uint8_t, 16> irk) {
    auto mac_opt = parse_mac_address(address);
    if (!mac_opt) {
        return false;
    }

    auto& mac = *mac_opt;

    // RPA format: hash (3 bytes) + prand (3 bytes)
    // MAC is big-endian, we need little-endian for crypto
    std::array<uint8_t, 6> rpa_le;
    std::reverse_copy(mac.begin(), mac.end(), rpa_le.begin());

    // Extract prand (upper 3 bytes of address = bytes 3-5 in LE)
    std::array<uint8_t, 3> prand;
    std::copy(rpa_le.begin() + 3, rpa_le.end(), prand.begin());

    // Extract hash (lower 3 bytes = bytes 0-2 in LE)
    std::array<uint8_t, 3> hash;
    std::copy(rpa_le.begin(), rpa_le.begin() + 3, hash.begin());

    // Compute expected hash
    auto computed_hash = address_hash(irk, prand);

    return hash == computed_hash;
}

std::optional<std::array<uint8_t, 16>> decrypt_ble_payload(std::span<const uint8_t> data,
                                                            std::span<const uint8_t, 16> key) {
    if (data.size() < 16) {
        return std::nullopt;
    }

    // Extract last 16 bytes
    std::array<uint8_t, 16> block;
    std::copy(data.end() - 16, data.end(), block.begin());

    // AES-CBC decrypt with zero IV
    AES_KEY aes_key;
    if (AES_set_decrypt_key(key.data(), 128, &aes_key) != 0) {
        return std::nullopt;
    }

    std::array<uint8_t, 16> iv{};  // Zero IV
    std::array<uint8_t, 16> output;

    AES_cbc_encrypt(block.data(), output.data(), 16, &aes_key, iv.data(), AES_DECRYPT);

    return output;
}

} // namespace airpods::crypto
