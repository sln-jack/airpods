#pragma once

#include <array>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>

namespace airpods::crypto {

// AES-128 encryption (block cipher, Bluetooth Core Spec function 'e')
// Returns empty array on failure
std::array<uint8_t, 16> aes_encrypt(std::span<const uint8_t, 16> key,
                                     std::span<const uint8_t, 16> data);

// Bluetooth address hash function 'ah' (Core Spec)
// Used for RPA verification
std::array<uint8_t, 3> address_hash(std::span<const uint8_t, 16> irk,
                                     std::span<const uint8_t, 3> prand);

// Verify if a Resolvable Private Address (RPA) matches an Identity Resolving Key (IRK)
bool verify_rpa(std::string_view address, std::span<const uint8_t, 16> irk);

// Decrypt the last 16 bytes of BLE advertisement data using AES-CBC with zero IV
std::optional<std::array<uint8_t, 16>> decrypt_ble_payload(std::span<const uint8_t> data,
                                                            std::span<const uint8_t, 16> key);

// Parse MAC address string (AA:BB:CC:DD:EE:FF) to bytes
std::optional<std::array<uint8_t, 6>> parse_mac_address(std::string_view address);

} // namespace airpods::crypto
