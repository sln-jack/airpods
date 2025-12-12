#include "l2cap.hpp"

#include <bluetooth/bluetooth.h>
#include <bluetooth/l2cap.h>
#include <bluetooth/sdp.h>
#include <bluetooth/sdp_lib.h>

#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cstring>
#include <iostream>

namespace l2cap {

Connection::Connection(Connection&& other) noexcept
    : fd(other.fd), address(std::move(other.address)) {
    other.fd = -1;
}

Connection& Connection::operator=(Connection&& other) noexcept {
    if (this != &other) {
        close();
        fd = other.fd;
        address = std::move(other.address);
        other.fd = -1;
    }
    return *this;
}

Connection::~Connection() {
    close();
}

void Connection::close() {
    if (fd >= 0) {
        ::close(fd);
        fd = -1;
    }
}

// Parse UUID string to uuid_t
// Format: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
static bool parse_uuid(const char* uuid_str, uuid_t* uuid) {
    uint32_t data0;
    uint16_t data1, data2, data3;
    uint32_t data4_hi;  // upper 2 bytes of last 6 bytes
    uint32_t data4_lo;  // lower 4 bytes of last 6 bytes

    if (sscanf(uuid_str, "%08x-%04hx-%04hx-%04hx-%04x%08x",
               &data0, &data1, &data2, &data3,
               &data4_hi, &data4_lo) != 6) {
        return false;
    }

    uuid->type = SDP_UUID128;
    uint8_t* p = uuid->value.uuid128.data;

    // UUID is stored big-endian
    p[0] = (data0 >> 24) & 0xff;
    p[1] = (data0 >> 16) & 0xff;
    p[2] = (data0 >> 8) & 0xff;
    p[3] = data0 & 0xff;
    p[4] = (data1 >> 8) & 0xff;
    p[5] = data1 & 0xff;
    p[6] = (data2 >> 8) & 0xff;
    p[7] = data2 & 0xff;
    p[8] = (data3 >> 8) & 0xff;
    p[9] = data3 & 0xff;
    // Last 6 bytes (12 hex chars): data4_hi (2 bytes) + data4_lo (4 bytes)
    p[10] = (data4_hi >> 8) & 0xff;
    p[11] = data4_hi & 0xff;
    p[12] = (data4_lo >> 24) & 0xff;
    p[13] = (data4_lo >> 16) & 0xff;
    p[14] = (data4_lo >> 8) & 0xff;
    p[15] = data4_lo & 0xff;

    return true;
}

// Look up PSM for UUID via SDP
static int lookup_psm(const bdaddr_t* target, const uuid_t* uuid) {
    bdaddr_t any = {{0, 0, 0, 0, 0, 0}};
    sdp_session_t* session = sdp_connect(&any, target, SDP_RETRY_IF_BUSY);
    if (!session) {
        std::cerr << "l2cap: SDP connect failed" << std::endl;
        return -1;
    }

    sdp_list_t* search_list = sdp_list_append(nullptr, const_cast<uuid_t*>(uuid));
    uint32_t range = 0x0000ffff;
    sdp_list_t* attrid_list = sdp_list_append(nullptr, &range);
    sdp_list_t* response_list = nullptr;

    int err = sdp_service_search_attr_req(session, search_list,
                                          SDP_ATTR_REQ_RANGE, attrid_list,
                                          &response_list);

    sdp_list_free(attrid_list, nullptr);
    sdp_list_free(search_list, nullptr);

    int psm = -1;

    if (err == 0 && response_list) {
        for (sdp_list_t* r = response_list; r; r = r->next) {
            sdp_record_t* rec = static_cast<sdp_record_t*>(r->data);
            sdp_list_t* proto_list = nullptr;

            if (sdp_get_access_protos(rec, &proto_list) == 0) {
                for (sdp_list_t* p = proto_list; p; p = p->next) {
                    sdp_list_t* pds = static_cast<sdp_list_t*>(p->data);
                    for (; pds; pds = pds->next) {
                        sdp_data_t* d = static_cast<sdp_data_t*>(pds->data);
                        int proto = 0;
                        for (; d; d = d->next) {
                            switch (d->dtd) {
                                case SDP_UUID16:
                                case SDP_UUID32:
                                case SDP_UUID128:
                                    proto = sdp_uuid_to_proto(&d->val.uuid);
                                    break;
                                case SDP_UINT8:
                                    if (proto == L2CAP_UUID) {
                                        psm = d->val.uint8;
                                    }
                                    break;
                                case SDP_UINT16:
                                    if (proto == L2CAP_UUID) {
                                        psm = d->val.uint16;
                                    }
                                    break;
                            }
                        }
                    }
                    sdp_list_free(static_cast<sdp_list_t*>(p->data), nullptr);
                }
                sdp_list_free(proto_list, nullptr);
            }
            sdp_record_free(rec);
        }
        sdp_list_free(response_list, nullptr);
    }

    sdp_close(session);
    return psm;
}

Connection connect(const std::string& mac_address) {
    // Parse MAC address
    bdaddr_t target;
    if (str2ba(mac_address.c_str(), &target) < 0) {
        std::cerr << "l2cap: invalid MAC address: " << mac_address << std::endl;
        return {};
    }

    // Parse UUID
    uuid_t uuid;
    if (!parse_uuid(AIRPODS_UUID, &uuid)) {
        std::cerr << "l2cap: failed to parse UUID" << std::endl;
        return {};
    }

    // Look up PSM via SDP
    int psm = lookup_psm(&target, &uuid);
    if (psm < 0) {
        std::cerr << "l2cap: SDP lookup failed for UUID" << std::endl;
        return {};
    }

    std::cout << "l2cap: found PSM " << psm << " for AirPods" << std::endl;

    // Create L2CAP socket
    int sock = socket(AF_BLUETOOTH, SOCK_SEQPACKET, BTPROTO_L2CAP);
    if (sock < 0) {
        std::cerr << "l2cap: socket creation failed" << std::endl;
        return {};
    }

    // Bind to local adapter
    struct sockaddr_l2 local_addr = {};
    local_addr.l2_family = AF_BLUETOOTH;
    memset(&local_addr.l2_bdaddr, 0, sizeof(local_addr.l2_bdaddr));
    local_addr.l2_psm = 0;

    if (bind(sock, reinterpret_cast<struct sockaddr*>(&local_addr), sizeof(local_addr)) < 0) {
        std::cerr << "l2cap: bind failed" << std::endl;
        ::close(sock);
        return {};
    }

    // Connect to remote device
    struct sockaddr_l2 remote_addr = {};
    remote_addr.l2_family = AF_BLUETOOTH;
    remote_addr.l2_bdaddr = target;
    remote_addr.l2_psm = htobs(psm);

    if (::connect(sock, reinterpret_cast<struct sockaddr*>(&remote_addr), sizeof(remote_addr)) < 0) {
        std::cerr << "l2cap: connect failed" << std::endl;
        ::close(sock);
        return {};
    }

    std::cout << "l2cap: connected to " << mac_address << std::endl;
    return Connection(sock, mac_address);
}

bool send(const Connection& conn, std::span<const uint8_t> data) {
    if (!conn.is_open()) return false;

    ssize_t written = ::send(conn.fd, data.data(), data.size(), 0);
    if (written < 0) {
        std::cerr << "l2cap: send failed" << std::endl;
        return false;
    }

    return static_cast<size_t>(written) == data.size();
}

std::vector<uint8_t> recv(const Connection& conn) {
    return recv_timeout(conn, 0);  // Non-blocking
}

std::vector<uint8_t> recv_timeout(const Connection& conn, int timeout_ms) {
    if (!conn.is_open()) return {};

    // Poll for data
    struct pollfd pfd = {};
    pfd.fd = conn.fd;
    pfd.events = POLLIN;

    int ret = poll(&pfd, 1, timeout_ms);
    if (ret <= 0) {
        return {};  // Timeout or error
    }

    if (!(pfd.revents & POLLIN)) {
        return {};
    }

    // Read data
    std::vector<uint8_t> buffer(1024);
    ssize_t n = ::recv(conn.fd, buffer.data(), buffer.size(), 0);
    if (n <= 0) {
        return {};
    }

    buffer.resize(static_cast<size_t>(n));
    return buffer;
}

} // namespace l2cap
