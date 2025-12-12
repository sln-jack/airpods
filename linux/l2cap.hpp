#pragma once

#include <cstdint>
#include <functional>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace l2cap {

// AirPods L2CAP PSM (derived from UUID)
// The actual connection uses UUID-based SDP lookup
constexpr const char* AIRPODS_UUID = "74ec2172-0bad-4d01-8f77-997b2be0722a";

// Connection result
struct Connection {
    int fd = -1;
    std::string address;

    bool is_open() const { return fd >= 0; }
    void close();

    // Move-only
    Connection() = default;
    Connection(int fd, std::string addr) : fd(fd), address(std::move(addr)) {}
    Connection(Connection&& other) noexcept;
    Connection& operator=(Connection&& other) noexcept;
    ~Connection();

    Connection(const Connection&) = delete;
    Connection& operator=(const Connection&) = delete;
};

// Connect to AirPods via L2CAP using UUID
// Returns connection with fd, or empty connection on failure
Connection connect(const std::string& mac_address);

// Send data to AirPods
bool send(const Connection& conn, std::span<const uint8_t> data);

// Receive data from AirPods (non-blocking if no data available)
// Returns empty vector on error or no data
std::vector<uint8_t> recv(const Connection& conn);

// Receive data with timeout (milliseconds, -1 for blocking)
std::vector<uint8_t> recv_timeout(const Connection& conn, int timeout_ms);

// Get file descriptor for poll/select
inline int get_fd(const Connection& conn) { return conn.fd; }

} // namespace l2cap
