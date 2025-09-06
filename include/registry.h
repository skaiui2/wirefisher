#pragma once
#include <vector>
#include <yaml-cpp/yaml.h>
struct EbpfModule {
    const char* name;
    const char* yaml_key;
    int  (*load)  (const YAML::Node& module_node);
    void (*unload)();
};

// 全局注册链单例
inline std::vector<const EbpfModule*>& get_registry() {
    static std::vector<const EbpfModule*> registry;
    return registry;
}

inline void register_module(const EbpfModule* m) {
    get_registry().push_back(m);
}

inline std::vector<struct ring_buffer*>& get_ringbufs() {
    static std::vector<struct ring_buffer*> rbs;
    return rbs;
}

inline void register_ringbuf(struct ring_buffer* rb) {
    get_ringbufs().push_back(rb);
}

