#pragma once

#include <cstdint>

namespace airpods {

enum class EarStatus : uint8_t {
    InEar = 0x00,
    NotInEar = 0x01,
    InCase = 0x02,
    Unknown = 0xFF,
};

struct EarDetection {
    EarStatus primary = EarStatus::Unknown;
    EarStatus secondary = EarStatus::Unknown;

    bool primary_in_ear() const { return primary == EarStatus::InEar; }
    bool secondary_in_ear() const { return secondary == EarStatus::InEar; }
    bool any_in_ear() const { return primary_in_ear() || secondary_in_ear(); }
    bool any_in_case() const { return primary == EarStatus::InCase || secondary == EarStatus::InCase; }
};

} // namespace airpods
