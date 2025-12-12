#include "pipewire.hpp"
#include <algorithm>
#include <cstring>
#include <iostream>
#include <atomic>

#include <pipewire/pipewire.h>
#include <spa/param/props.h>
#include <spa/pod/builder.h>

namespace pipewire {

namespace {

struct Context {
    pw_main_loop* loop = nullptr;
    pw_context* context = nullptr;
    pw_core* core = nullptr;
    pw_registry* registry = nullptr;
    spa_hook registry_listener{};
    spa_hook core_listener{};
    std::string target_mac;
    std::atomic<bool> found{false};
    int sync_seq = 0;
};

std::string extract_mac_from_node_name(const char* node_name) {
    // Format: bluez_output.XX_XX_XX_XX_XX_XX.N
    std::string name(node_name);
    auto dot1 = name.find('.');
    if (dot1 == std::string::npos) return {};
    auto dot2 = name.find('.', dot1 + 1);
    if (dot2 == std::string::npos) return {};

    std::string mac = name.substr(dot1 + 1, dot2 - dot1 - 1);
    std::replace(mac.begin(), mac.end(), '_', ':');
    return mac;
}

void on_core_done(void* data, uint32_t id, int seq) {
    auto* ctx = static_cast<Context*>(data);
    if (id == PW_ID_CORE && seq == ctx->sync_seq)
        pw_main_loop_quit(ctx->loop);
}

void on_core_error(void*, uint32_t, int, int, const char* msg) {
    std::cerr << "pipewire error: " << msg << std::endl;
}

const pw_core_events core_events = {
    .version = PW_VERSION_CORE_EVENTS,
    .done = on_core_done,
    .error = on_core_error,
};

void on_registry_global(void* data, uint32_t id, uint32_t, const char* type,
                        uint32_t, const spa_dict* props) {
    auto* ctx = static_cast<Context*>(data);

    if (!props || strcmp(type, PW_TYPE_INTERFACE_Node) != 0)
        return;

    const char* node_name = spa_dict_lookup(props, "node.name");
    if (!node_name || !strstr(node_name, "bluez"))
        return;

    std::string node_mac = extract_mac_from_node_name(node_name);
    if (node_mac.empty())
        return;

    // Case-insensitive MAC comparison
    std::string target = ctx->target_mac;
    std::transform(node_mac.begin(), node_mac.end(), node_mac.begin(), ::toupper);
    std::transform(target.begin(), target.end(), target.begin(), ::toupper);
    if (node_mac != target)
        return;

    // Found matching node - disable suspend timeout
    auto* proxy = static_cast<pw_proxy*>(
        pw_registry_bind(ctx->registry, id, type, PW_VERSION_NODE, 0));
    if (!proxy) return;

    uint8_t buffer[256];
    spa_pod_builder b;
    spa_pod_builder_init(&b, buffer, sizeof(buffer));

    spa_pod_frame f, f2;
    spa_pod_builder_push_object(&b, &f, SPA_TYPE_OBJECT_Props, SPA_PARAM_Props);
    spa_pod_builder_prop(&b, SPA_PROP_unknown, 0);
    spa_pod_builder_push_struct(&b, &f2);
    spa_pod_builder_string(&b, "session.suspend-timeout-seconds");
    spa_pod_builder_string(&b, "0");
    spa_pod_builder_pop(&b, &f2);
    auto* pod = static_cast<spa_pod*>(spa_pod_builder_pop(&b, &f));

    pw_node_set_param(reinterpret_cast<pw_node*>(proxy), SPA_PARAM_Props, 0, pod);
    pw_proxy_destroy(proxy);

    ctx->found = true;
    std::cout << "pipewire: disabled suspend timeout for " << ctx->target_mac << std::endl;
}

const pw_registry_events registry_events = {
    .version = PW_VERSION_REGISTRY_EVENTS,
    .global = on_registry_global,
};

} // anonymous namespace

bool disable_suspend_timeout(const std::string& mac_address) {
    pw_init(nullptr, nullptr);

    Context ctx;
    ctx.target_mac = mac_address;

    ctx.loop = pw_main_loop_new(nullptr);
    if (!ctx.loop) return false;

    ctx.context = pw_context_new(pw_main_loop_get_loop(ctx.loop), nullptr, 0);
    if (!ctx.context) {
        pw_main_loop_destroy(ctx.loop);
        return false;
    }

    ctx.core = pw_context_connect(ctx.context, nullptr, 0);
    if (!ctx.core) {
        pw_context_destroy(ctx.context);
        pw_main_loop_destroy(ctx.loop);
        return false;
    }

    pw_core_add_listener(ctx.core, &ctx.core_listener, &core_events, &ctx);

    ctx.registry = pw_core_get_registry(ctx.core, PW_VERSION_REGISTRY, 0);
    if (!ctx.registry) {
        pw_core_disconnect(ctx.core);
        pw_context_destroy(ctx.context);
        pw_main_loop_destroy(ctx.loop);
        return false;
    }

    pw_registry_add_listener(ctx.registry, &ctx.registry_listener, &registry_events, &ctx);
    ctx.sync_seq = pw_core_sync(ctx.core, PW_ID_CORE, 0);

    // Timeout after 2 seconds
    auto* loop = pw_main_loop_get_loop(ctx.loop);
    auto* timer = pw_loop_add_timer(loop, [](void* d, uint64_t) {
        pw_main_loop_quit(static_cast<Context*>(d)->loop);
    }, &ctx);
    timespec ts = {2, 0};
    pw_loop_update_timer(loop, timer, &ts, nullptr, false);

    pw_main_loop_run(ctx.loop);

    // Cleanup
    pw_loop_destroy_source(loop, timer);
    pw_proxy_destroy(reinterpret_cast<pw_proxy*>(ctx.registry));
    pw_core_disconnect(ctx.core);
    pw_context_destroy(ctx.context);
    pw_main_loop_destroy(ctx.loop);

    return ctx.found;
}

} // namespace pipewire
