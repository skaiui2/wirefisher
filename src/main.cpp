#include "registry.h"
#include <iostream>
#include <signal.h>
#include <unistd.h>

#include <iostream>
#include <yaml-cpp/yaml.h>
#include <cstdint>
#include <string>
#include <regex>
#include <signal.h>
#include <unistd.h>
#include <iostream>
#include <cstring>
#include <getopt.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <linux/netfilter.h>
#include <linux/bpf.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <errno.h>

static bool running = true;

static void on_signal(int) {
    running = false;
}

extern void out();
int main() {
    signal(SIGINT,  on_signal);
    signal(SIGTERM, on_signal);

    for (auto m : get_registry()) {
        std::cout << "加载模块：" << m->name << std::endl;
        if (m->load() != 0) {
            std::cerr << "  模块加载失败：" << m->name << std::endl;
        }
    }

    while (running) {
        out();
    }

    auto& regs = get_registry();
    for (auto it = regs.rbegin(); it != regs.rend(); ++it) {
        std::cout << "卸载模块：" << (*it)->name << std::endl;
        (*it)->unload();
    }

    return 0;
}
