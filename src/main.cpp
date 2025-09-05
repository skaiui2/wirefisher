#include "registry.h"
#include <iostream>
#include <signal.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include <yaml-cpp/yaml.h>

static bool running = true;

static void on_signal(int) {
    running = false;
}

extern void out();
int main()
{
    if (getuid() != 0) {
        std::cerr << "error: no root!\n";
        return 1;
    }

    YAML::Node config = YAML::LoadFile("../config/config.yaml");

    signal(SIGINT,  on_signal);
    signal(SIGTERM, on_signal);

    // 4. 遍历注册链，按配置节判断是否加载模块
    for (auto mod : get_registry()) {
        const auto& node = config[mod->yaml_key];  // 每个模块声明自己的 yaml_key
        if (!node || node.IsNull()) {
            std::cout << "跳过模块：" << mod->name << "（未配置）\n";
            continue;
        }

        std::cout << "加载模块：" << mod->name << "\n";
        if (mod->load() != 0) {
            std::cerr << "模块加载失败：" << mod->name << "\n";
        }
    }

    while (running) {
        for (auto rb : get_ringbufs()) {
            int err = ring_buffer__poll(rb, 100);
            if (err == -EINTR) {
                continue;
            } else if (err < 0) {
                std::cerr << "ring_buffer__poll 错误: " << err << "\n";
            }
        }
    }

    auto& regs = get_registry();
    for (auto it = regs.rbegin(); it != regs.rend(); ++it) {
        std::cout << "卸载模块的注册：" << (*it)->name << std::endl;
        (*it)->unload();
    }

    return 0;
}
