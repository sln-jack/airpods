#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <unordered_map>
#include <optional>

namespace airpods {

enum class NoiseControlMode : uint8_t {
    Off = 0,
    NoiseCancellation = 1,
    Transparency = 2,
    Adaptive = 3,
};

constexpr uint8_t noise_control_mode_min = 0;
constexpr uint8_t noise_control_mode_max = 3;

inline std::string_view to_string(NoiseControlMode mode) {
    switch (mode) {
        case NoiseControlMode::Off: return "off";
        case NoiseControlMode::NoiseCancellation: return "anc";
        case NoiseControlMode::Transparency: return "transparency";
        case NoiseControlMode::Adaptive: return "adaptive";
    }
    return "unknown";
}

inline std::optional<NoiseControlMode> noise_control_mode_from_string(std::string_view s) {
    if (s == "off") return NoiseControlMode::Off;
    if (s == "anc" || s == "noise_cancellation") return NoiseControlMode::NoiseCancellation;
    if (s == "transparency") return NoiseControlMode::Transparency;
    if (s == "adaptive") return NoiseControlMode::Adaptive;
    return std::nullopt;
}

enum class Model {
    Unknown,
    AirPods1,
    AirPods2,
    AirPods3,
    AirPods4,
    AirPods4ANC,
    AirPodsPro,
    AirPodsPro2Lightning,
    AirPodsPro2USBC,
    AirPodsMaxLightning,
    AirPodsMaxUSBC,
};

inline std::string_view to_string(Model model) {
    switch (model) {
        case Model::Unknown: return "unknown";
        case Model::AirPods1: return "airpods_1";
        case Model::AirPods2: return "airpods_2";
        case Model::AirPods3: return "airpods_3";
        case Model::AirPods4: return "airpods_4";
        case Model::AirPods4ANC: return "airpods_4_anc";
        case Model::AirPodsPro: return "airpods_pro";
        case Model::AirPodsPro2Lightning: return "airpods_pro_2";
        case Model::AirPodsPro2USBC: return "airpods_pro_2_usbc";
        case Model::AirPodsMaxLightning: return "airpods_max";
        case Model::AirPodsMaxUSBC: return "airpods_max_usbc";
    }
    return "unknown";
}

// Model numbers from https://support.apple.com/en-us/109525
inline Model model_from_model_number(std::string_view model_number) {
    static const std::unordered_map<std::string_view, Model> model_map = {
        {"A1523", Model::AirPods1},
        {"A1722", Model::AirPods1},
        {"A2032", Model::AirPods2},
        {"A2031", Model::AirPods2},
        {"A2084", Model::AirPodsPro},
        {"A2083", Model::AirPodsPro},
        {"A2096", Model::AirPodsMaxLightning},
        {"A3184", Model::AirPodsMaxUSBC},
        {"A2565", Model::AirPods3},
        {"A2564", Model::AirPods3},
        {"A3047", Model::AirPodsPro2USBC},
        {"A3048", Model::AirPodsPro2USBC},
        {"A3049", Model::AirPodsPro2USBC},
        {"A2931", Model::AirPodsPro2Lightning},
        {"A2699", Model::AirPodsPro2Lightning},
        {"A2698", Model::AirPodsPro2Lightning},
        {"A3053", Model::AirPods4},
        {"A3050", Model::AirPods4},
        {"A3054", Model::AirPods4},
        {"A3056", Model::AirPods4ANC},
        {"A3055", Model::AirPods4ANC},
        {"A3057", Model::AirPods4ANC},
    };

    auto it = model_map.find(model_number);
    return it != model_map.end() ? it->second : Model::Unknown;
}

inline bool is_headset(Model model) {
    return model == Model::AirPodsMaxLightning || model == Model::AirPodsMaxUSBC;
}

} // namespace airpods
