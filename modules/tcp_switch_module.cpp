#include "registry.h"
#include <iostream>
#include <yaml-cpp/yaml.h>
#include <cstdint>
#include <cstring>
#include <string>
#include <thread>
#include <atomic>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include "parse.h"
#include <nlohmann/json.hpp>
#include "kafka_producer.h"

extern KafkaProducer *g_producer;

struct message_get {
    __u64 ret;
    __u64 timestamp;
};

struct cc_rule {
    struct ip_addr ip;
    __u16 port;
    char algo[16];
    __u8 remote : 1;
};

static struct bpf_object *obj = nullptr;
static int sockops_cgroup_fd = -1;
static struct ring_buffer *rb = nullptr;
static std::atomic<bool> rb_running{false};
static std::thread rb_thread;

static int get_rule(const YAML::Node& module_node)
{
    struct cc_rule rule = {0};
    const auto& node = module_node["tcp_switch_rule"];
    if (!node || node.IsNull()) {
        std::cerr << "[tcp_switch] 缺少 tcp_switch_rule 配置\n";
        return -1;
    }

    char *algo = rule.algo;

    try {
        rule.ip = parse_ip(node["ip"].as<std::string>());
        rule.port = node["port"].as<uint16_t>();
        rule.remote = parse_flag(node["remote"]);

        std::string cc_name = node["congestion"].as<std::string>();

        if (cc_name.size() >= sizeof(algo)) {
            std::cerr << "[tcp_switch] 拥塞控制算法名过长: " << cc_name << "\n";
            return -1;
        }
        std::memcpy(algo, cc_name.c_str(), cc_name.size());
    }
    catch (const std::exception& e) {
        std::cerr << "[tcp_switch] 配置解析失败: " << e.what() << "\n";
        return -1;
    }

    std::cout 
        << "=== tcp_switch_rule ===\n"
        << " ip         : " << ip_to_string(rule.ip) << "\n"
        << " port       : " << rule.port << "\n"
        << " remote     : " << (rule.remote ? "true" : "false") << "\n"
        << " congestion : " << algo << "\n"
        << "========================\n";

    struct bpf_map *map = bpf_object__find_map_by_name(obj, "cc_map");
    if (!map) {
        std::cerr << "[tcp_switch] error: can't find cc_map\n";
        return -1;
    }

    int map_fd = bpf_map__fd(map);
    int key = 0;
    int err = bpf_map_update_elem(map_fd, &key, &rule, BPF_ANY);
    if (err) {
        std::cerr << "[tcp_switch] 更新 cc_map 失败: " << strerror(errno) << "\n";
        return -1;
    }

    return 1;
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
    if (data_sz != sizeof(message_get)) {
        std::cerr << "[tcp_switch] 数据大小不匹配: " << data_sz
                  << " (期望 " << sizeof(message_get) << ")\n";
        return 0;
    }

    const auto *e = static_cast<const message_get *>(data);

    std::cout << "[tcp_switch] cc_switch result: ret=" << e->ret
              << " timestamp=" << format_elapsed_ns(e->timestamp) << "\n";

    if (g_producer) {
        nlohmann::json j = {
            {"ret", e->ret},
            {"timestamp", format_elapsed_ns(e->timestamp)}
        };
        g_producer->send("", j.dump());
    }

    return 0;
}


static int load_tcp_switch_module(const YAML::Node &module_node)
{
    int prog_fd;
    int cgroup_fd;
    if (getuid() != 0) {
        std::cerr << "[tcp_switch] 错误：需要 root 权限\n";
        return -1;
    }

    obj = bpf_object__open_file("../bpf/build/tc_cc_switch.o", nullptr);
    if (libbpf_get_error(obj)) {
        int err = libbpf_get_error(obj);
        std::cerr << "[tcp_switch] 打开 BPF 对象失败: " << strerror(-err) << "\n";
        obj = nullptr;
        return -1;
    }

    int err = bpf_object__load(obj);
    if (err) {
        std::cerr << "[tcp_switch] 加载 BPF 对象失败: " << strerror(-err) << "\n";
        bpf_object__close(obj);
        obj = nullptr;
        return -1;
    }

    if (!get_rule(module_node)) {
        std::cerr << "[tcp_switch] 读取配置或更新规则失败\n";
    }

    struct bpf_program *prog =
        bpf_object__find_program_by_name(obj, "cc_switch_sockops");
    if (!prog) {
        std::cerr << "[tcp_switch] 找不到程序 cc_switch_sockops\n";
        goto error;
    }

    prog_fd = bpf_program__fd(prog);

    cgroup_fd = open("/sys/fs/cgroup", O_RDONLY);
    if (cgroup_fd < 0) {
        std::cerr << "[tcp_switch] 打开 cgroup 失败: "
                  << strerror(errno) << "\n";
        goto error;
    }

    if (bpf_prog_attach(prog_fd, cgroup_fd, BPF_CGROUP_SOCK_OPS, 0) < 0) {
        std::cerr << "[tcp_switch] 附加 sockops 程序失败: "
                  << strerror(errno) << "\n";
        close(cgroup_fd);
        goto error;
    }

    sockops_cgroup_fd = cgroup_fd;

    {
        auto map = bpf_object__find_map_by_name(obj, "ringbuf");
        if (!map) {
            std::cerr << "[tcp_switch] 找不到 ringbuf map\n";
            goto error;
        }

        int map_fd = bpf_map__fd(map);
        rb = ring_buffer__new(map_fd, handle_event, nullptr, nullptr);
        if (!rb) {
            std::cerr << "[tcp_switch] 创建 ring buffer 失败\n";
            goto error;
        }

        register_ringbuf(rb);
    }

    std::cout << "[tcp_switch] 模块加载完成，已附加 sockops 程序\n";
    return 0;

error:
    if (sockops_cgroup_fd >= 0) {
        close(sockops_cgroup_fd);
        sockops_cgroup_fd = -1;
    }
    if (obj) {
        bpf_object__close(obj);
        obj = nullptr;
    }
    return -1;
}

static void unload_tcp_switch_module()
{
    if (rb)
        ring_buffer__free(rb);

    if (obj && sockops_cgroup_fd >= 0) {
        struct bpf_program *prog =
            bpf_object__find_program_by_name(obj, "cc_switch_sockops");
        if (prog) {
            int prog_fd = bpf_program__fd(prog);
            bpf_prog_detach2(prog_fd, sockops_cgroup_fd, BPF_CGROUP_SOCK_OPS);
        }
    }

    if (sockops_cgroup_fd >= 0) {
        close(sockops_cgroup_fd);
        sockops_cgroup_fd = -1;
    }

    if (obj) {
        bpf_object__close(obj);
        obj = nullptr;
    }

    std::cout << "[tcp_switch] 模块已卸载\n";
}

static const EbpfModule tcp_switch_module = {
    "tcp_switch",        
    "tcp_switch_module",  
    load_tcp_switch_module,
    unload_tcp_switch_module
};

__attribute__((constructor))
static void register_tcp_switch_module()
{
    register_module(&tcp_switch_module);
}