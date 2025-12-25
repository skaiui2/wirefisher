#include "registry.h"
#include "parse.h"              
#include <bpf/libbpf.h>
#include <linux/bpf.h>
#include <unistd.h>
#include <signal.h>
#include <iostream>
#include <cstring>
#include <net/if.h>
#include <yaml-cpp/yaml.h>
#include <signal.h>
#include <cstring>
#include <getopt.h>
#include <arpa/inet.h>
#include <bpf/libbpf.h>
#include <nlohmann/json.hpp>
#include "kafka_producer.h"

extern KafkaProducer *g_producer;

struct eth_rule {
    __u64    rate_bps;      
    __u32    time_scale;    
    __u8     gress;       
};

struct message_get {
    struct flow_rate_message flow_msg;
};

static struct bpf_object  *obj               = nullptr;
static bool                hook_created_e    = false;
static bool                hook_created_i    = false;
static bool                attached_e        = false;
static bool                attached_i        = false;
static struct ring_buffer *rb                = nullptr;
static struct bpf_tc_hook  hook_e            = {};
static struct bpf_tc_hook  hook_i            = {};
static struct bpf_tc_opts  opts_e            = {};
static struct bpf_tc_opts  opts_i            = {};

static unsigned int ifindex = 0;

static int get_rule(const YAML::Node& module_node)
{
    struct eth_rule rule = {0};
    const auto& node = module_node["eth_rule"];
    if (!node || node.IsNull()) {
        std::cerr << "[get_rule] 缺少 eth_rule 配置\n";
        return -1;
    }

    try {
        ifindex = if_nametoindex(node["target_if"].as<std::string>().c_str());
        rule.rate_bps        = parse_rate_bps(node["rate_bps"].as<std::string>());
        rule.time_scale      = parse_time_scale(node["time_scale"].as<std::string>());
        rule.gress           = parse_gress(node["gress"].as<std::string>());
    }
    catch (const std::exception& e) {
        std::cerr << "[get_rule] 配置解析失败: " << e.what() << "\n";
        return -1;
    }

    std::cout 
        << "=== eth_rule ===\n"
        << " rate_bps          : " << rule.rate_bps << " bps\n"
        << " time_scale        : " << rule.time_scale << " sec\n"
        << " gress             : " << (rule.gress ? "egress" : "ingress") << "\n"
        << "========================\n";

    struct bpf_map *map = bpf_object__find_map_by_name(obj, "eth_rules");
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
    if (data_sz != sizeof(message_get)) {
        std::cerr << "数据大小不匹配: " << data_sz << " (期望 " << sizeof(message_get) << ")\n";
        return 0;
    }

    auto* e = static_cast<const message_get*>(data);
    
    std::cout << std::fixed << std::setprecision(2) 
    << "=== process_traffic ===\n" 
    << " instant_rate_bps : " << e->flow_msg.instance_rate_bps / 1024.0 / 1024.0 << " MB/s\n"
    << " rate_bps         : " << e->flow_msg.rate_bps / 1024.0 / 1024.0 << " MB/s\n"
    << " peak_rate_bps    : " << e->flow_msg.peak_rate_bps / 1024.0 / 1024.0 << " MB/s\n"
    << " smoothed_rate_bps: " << e->flow_msg.smooth_rate_bps / 1024.0 / 1024.0 << " MB/s\n"
    << " timestamp         : " << format_elapsed_ns(e->flow_msg.timestamp) << "\n"
    << "=====================\n";

    nlohmann::json j = {
        {"instant_rate_bps", e->flow_msg.instance_rate_bps / (1024.0 * 1024.0)},
        {"rate_bps", e->flow_msg.rate_bps / (1024.0 * 1024.0)},
        {"peak_rate_bps", e->flow_msg.peak_rate_bps / (1024.0 * 1024.0)},
        {"smoothed_rate_bps", e->flow_msg.smooth_rate_bps / (1024.0 * 1024.0)},
        {"timestamp", format_elapsed_ns(e->flow_msg.timestamp)}
    };

    if (g_producer) {
        g_producer->send("", j.dump());
    }

    return 0;
}

static int load_eth_module(const YAML::Node &module_node) 
{
    int fd_e;
    int fd_i;
    struct bpf_program *prog_e;
    struct bpf_program *prog_i;
    int err;

    if (getuid() != 0) {
        std::cerr << "[tc_eth] 错误：需要 root 权限\n";
        return -1;
    }

    obj = bpf_object__open_file("../bpf/build/tc_eth.o", nullptr);
    if (!obj) {
        std::cerr << "[tc_eth_module] bpf_object__open_file 失败\n";
        return -1;
    }
    if (int err = bpf_object__load(obj)) {
        std::cerr << "[tc_eth_module] bpf_object__load 失败: " << err << "\n";
        bpf_object__close(obj);
        obj = nullptr;
        return -1;
    }

    if (get_rule(module_node) == false) {
        std::cerr << "[tc_eth] 读取配置或更新规则失败\n";
        goto error;
    }

    prog_e = bpf_object__find_program_by_name(obj, "tc_egress");
    prog_i = bpf_object__find_program_by_name(obj, "tc_ingress");
    if (!prog_e || !prog_i) {
        std::cerr << "[tc_eth_module] 找不到 tc_egress 或 tc_ingress\n";
        goto error;
    }

    fd_e = bpf_program__fd(prog_e);
    fd_i = bpf_program__fd(prog_i);

    hook_e.sz           = sizeof(hook_e);
    hook_e.ifindex      = (int)ifindex;
    hook_e.attach_point = BPF_TC_EGRESS;
    hook_i.sz           = sizeof(hook_i);
    hook_i.ifindex      = (int)ifindex;
    hook_i.attach_point = BPF_TC_INGRESS;

    opts_e.sz    = sizeof(opts_e);
    opts_e.handle   = 1;
    opts_e.priority = 1;
    opts_i.sz    = sizeof(opts_i);
    opts_i.handle   = 1;
    opts_i.priority = 1;

    err = bpf_tc_hook_create(&hook_e);
    if (err && err != -EEXIST) {
        std::cerr << "[tc_eth_module] create egress hook 失败: " << strerror(-err) << "\n";
        goto error;
    }

    hook_created_e = true;

    err = bpf_tc_hook_create(&hook_i);
    if (err && err != -EEXIST) {
        std::cerr << "[tc_eth_module] create ingress hook 失败: "
                << strerror(-err) << "\n";
        goto error;
    }
    
    hook_created_i = true;

    opts_e.prog_fd = fd_e;
    if (err = bpf_tc_attach(&hook_e, &opts_e)) {
        std::cerr << "[tc_eth_module] attach egress 失败: "
                  << strerror(-err) << "\n";
        goto error;
    }
    attached_e = true;

    opts_i.prog_fd = fd_i;
    if (err = bpf_tc_attach(&hook_i, &opts_i)) {
        std::cerr << "[tc_attach_module] attach ingress 失败: "
                  << strerror(-err) << "\n";
        goto error;
    }
    attached_i = true;


    {
        auto map = bpf_object__find_map_by_name(obj, "ringbuf");
        int map_fd = bpf_map__fd(map);
        rb = ring_buffer__new(map_fd, handle_event, nullptr, nullptr);
        if (!rb) {
            std::cerr << "[tc_eth] 创建 ring buffer 失败\n";
            goto error;
        }
        register_ringbuf(rb);
    }

    std::cout << "[tc_eth_module] 程序已附加到 ifindex=" 
              << ifindex << " (egress & ingress)\n";
    return 0;

error:
    if (attached_i) {
        opts_i.flags = opts_i.prog_fd = opts_i.prog_id = 0;
        bpf_tc_detach(&hook_i, &opts_i);
    }
    if (attached_e) {
        opts_e.flags = opts_e.prog_fd = opts_e.prog_id = 0;
        bpf_tc_detach(&hook_e, &opts_e);
    }
    if (hook_created_i) bpf_tc_hook_destroy(&hook_i);
    if (hook_created_e) bpf_tc_hook_destroy(&hook_e);
    if (obj) {
        bpf_object__close(obj);
        obj = nullptr;
    }
    return -1;
}

static void unload_eth_module() 
{
    if (attached_i) {
        opts_i.flags = opts_i.prog_fd = opts_i.prog_id = 0;
        bpf_tc_detach(&hook_i, &opts_i);
    }
    if (attached_e) {
        opts_e.flags = opts_e.prog_fd = opts_e.prog_id = 0;
        bpf_tc_detach(&hook_e, &opts_e);
    }
    if (hook_created_i) bpf_tc_hook_destroy(&hook_i);
    if (hook_created_e) bpf_tc_hook_destroy(&hook_e);
    if (obj) {
        bpf_object__close(obj);
        obj = nullptr;
    }
    std::cout << "[tc_eth_module] 模块已卸载\n";
}

static const EbpfModule tc_module = {
    "tc_eth",         
    "eth_module",        
    load_eth_module,
    unload_eth_module
};

__attribute__((constructor))
static void register_tc_module()
{
    register_module(&tc_module);
}

