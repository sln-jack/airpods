#pragma once

#include <string>

namespace pipewire {

// Disable suspend timeout for a Bluetooth audio device to prevent audio delay
bool disable_suspend_timeout(const std::string& mac_address);

} // namespace pipewire
