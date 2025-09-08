#include "registry.h"
#include "parse.h"              
#include <bpf/libbpf.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <cstring>
#include <bpf/bpf.h>
#include <unistd.h>
#include <fcntl.h>
#include <iostream>
#include <yaml-cpp/yaml.h>

struct message_get {   
    __u64 instance_rate_bps; 
    __u64 rate_bps;
    __u64 peak_rate_bps;
    __u64 smoothed_rate_bps;
	__u64 timestamp;
};

struct cgroup_rule {
	uint64_t rate_bps;	
	uint8_t gress;
	uint32_t time_scale;
};

static struct bpf_object   *obj         = nullptr;
static int                  cgroup_fd   = -1;
static int                  fd_egress   = -1;
static int                  fd_ingress  = -1;
static struct ring_buffer  *rb          = nullptr;
static bool                 attached_e   = false;
static bool                 attached_i   = false;
static std::string cgroup_path;

static int get_rule(const YAML::Node& module_node)
{
    struct cgroup_rule rule = {0};
    const auto& node = module_node["cgroup_rule"];
    if (!node || node.IsNull()) {
        std::cerr << "[get_rule] 缺少 cgroup_rule 配置\n";
        return -1;
    }

    try {
        cgroup_path          = node["target_cgroup"].as<std::string>();
        rule.rate_bps        = parse_rate_bps(node["rate_bps"].as<std::string>());
        rule.time_scale      = parse_time_scale(node["time_scale"].as<std::string>());
        rule.gress           = parse_gress(node["gress"].as<std::string>());
    }
    catch (const std::exception& e) {
        std::cerr << "[get_rule] 配置解析失败: " << e.what() << "\n";
        return -1;
    }

    std::cout 
        << "=== cgroup_rule ===\n"
        << " rate_bps          : " << rule.rate_bps << " bps\n"
        << " time_scale        : " << rule.time_scale << " sec\n"
        << " gress             : " << (rule.gress ? "egress" : "ingress") << "\n"
        << "========================\n";

    struct bpf_map *map = bpf_object__find_map_by_name(obj, "cgroup_rules");
	if (!map) {
        std::cout << "error: can't find the rule map" << "\n";
        return false;
	}

	uint32_t key = 0;
	int err = bpf_map__update_elem(map,&key, sizeof(key), &rule, sizeof(rule), BPF_ANY);
	if (err) {
        std::cout << "NO3" << "\n";
        return false;
	}
    return true;
}


static int handle_event(void* ctx, void* data, size_t data_sz) {
    if (data_sz != sizeof(message_get))
        return 0;

    auto* e = static_cast<const message_get*>(data);
    std::cout << std::fixed << std::setprecision(2) 
    << "=== process_traffic ===\n" 
    << " instant_rate_bps : " << e->instance_rate_bps / 1024.0 / 1024.0 << " MB/s\n"
    << " rate_bps         : " << e->rate_bps / 1024.0 / 1024.0 << " MB/s\n"
    << " peak_rate_bps    : " << e->peak_rate_bps / 1024.0 / 1024.0 << " MB/s\n"
    << " smoothed_rate_bps: " << e->smoothed_rate_bps / 1024.0 / 1024.0 << " MB/s\n"
    << " timestamp         : " << format_elapsed_ns(e->timestamp) << "\n"
    << "=====================\n";


    return 0;
}


static int load_cgroup_module(const YAML::Node &module_node) 
{
    if (getuid() != 0) {
        std::cerr << "[cgroup_module] 需要 root 权限\n";
        return -1;
    }

    const auto &node = module_node["cgroup_rule"];
    if (!node || node.IsNull()) {
        std::cerr << "[cgroup_module] 缺少 cgroup_rule 配置\n";
        return -1;
    }

    obj = bpf_object__open_file("../bpf/build/tc_cgroup.o", nullptr);
    if (!obj) {
        std::cerr << "[cgroup_module] bpf_object__open_file 失败\n";
        return -1;
    }

    if (int err = bpf_object__load(obj)) {
        std::cerr << "[cgroup_module] bpf_object__load 失败: " << err << "\n";
        bpf_object__close(obj);
        obj = nullptr;
        return -1;
    }

    if (!get_rule(module_node)) {
        std::cerr << "[cgroup_module] setup_cgroup_rules 失败\n";
        goto error;
    }

    cgroup_fd = open(cgroup_path.c_str(), O_RDONLY);
    if (cgroup_fd < 0) {
        std::cerr << "[cgroup_module] 打开 CGroup 失败: "
                  << cgroup_path << " (" << strerror(errno) << ")\n";
        goto error;
    }


    {
        auto *p = bpf_object__find_program_by_name(obj, "cgroup_skb_egress");
        if (!p) {
            std::cerr << "[cgroup_module] 找不到 BPF 程序: cgroup_skb_egress\n";
            goto error;
        }
        fd_egress = bpf_program__fd(p);
        if (int err = bpf_prog_attach(fd_egress, cgroup_fd,
                                      BPF_CGROUP_INET_EGRESS, 0)) {
            std::cerr << "[cgroup_module] attach EGRESS 失败: "
                      << strerror(-err) << "\n";
            goto error;
        }
        attached_e = true;
    }

    {
        auto *p = bpf_object__find_program_by_name(obj, "cgroup_skb_ingress");
        if (!p) {
            std::cerr << "[cgroup_module] 找不到 BPF 程序: cgroup_skb_ingress\n";
            goto error;
        }
        fd_ingress = bpf_program__fd(p);
        if (int err = bpf_prog_attach(fd_ingress, cgroup_fd,
                                      BPF_CGROUP_INET_INGRESS, 0)) {
            std::cerr << "[cgroup_module] attach INGRESS 失败: "
                      << strerror(-err) << "\n";
            goto error;
        }
        attached_i = true;
    }

    std::cout << "[cgroup_module] 已附加 EGRESS+INGRESS 到 "
              << cgroup_path << "\n";

    {
        auto *map = bpf_object__find_map_by_name(obj, "ringbuf");
        int map_fd = bpf_map__fd(map);
        rb = ring_buffer__new(map_fd, handle_event, nullptr, nullptr);
        if (!rb) {
            std::cerr << "[cgroup_module] 创建 ring buffer 失败\n";
            goto error;
        }
        register_ringbuf(rb);
    }

    std::cout << "[cgroup_module] 启动流量监控...\n";
    return 0;

    
error:
    if (attached_i) {
        auto *p = bpf_object__find_program_by_name(obj, "cgroup_skb_ingress");
        bpf_prog_detach2(bpf_program__fd(p), cgroup_fd,
                         BPF_CGROUP_INET_INGRESS);
    }
    if (attached_e) {
        auto *p = bpf_object__find_program_by_name(obj, "cgroup_skb_egress");
        bpf_prog_detach2(bpf_program__fd(p), cgroup_fd,
                         BPF_CGROUP_INET_EGRESS);
    }
    if (cgroup_fd >= 0) {
        close(cgroup_fd);
        cgroup_fd = -1;
    }
    return -1;
}

static void unload_cgroup_module() {
    if (attached_i) {
        bpf_prog_detach2(fd_ingress, cgroup_fd, BPF_CGROUP_INET_INGRESS);
        attached_i = false;
    }
    if (attached_e) {
        bpf_prog_detach2(fd_egress, cgroup_fd, BPF_CGROUP_INET_EGRESS);
        attached_e = false;
    }
    if (cgroup_fd >= 0) {
        close(cgroup_fd);
        cgroup_fd = -1;
    }
    if (rb) {
        ring_buffer__free(rb);
        rb = nullptr;
    }
    if (obj) {
        bpf_object__close(obj);
        obj = nullptr;
    }
    std::cout << "[cgroup_module] 模块已卸载\n";
}


static const EbpfModule cgroup_module = {
    "tc_cgroup",       
    "cgroup_module",        
    load_cgroup_module,
    unload_cgroup_module
};

__attribute__((constructor))
static void _register_cgroup_module() {
    register_module(&cgroup_module);
}