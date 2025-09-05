#pragma once
#include <vector>

// 每个模块只需提供：模块名 + load()/unload() 指针
struct EbpfModule {
    const char* name;
    int  (*load)  ();
    void (*unload)();
};

// 全局注册链单例
inline std::vector<const EbpfModule*>& get_registry() {
    static std::vector<const EbpfModule*> registry;
    return registry;
}

// 把模块加入全局注册链
inline void register_module(const EbpfModule* m) {
    get_registry().push_back(m);
}
