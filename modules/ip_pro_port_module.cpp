#include "registry.h"
#include "parse.h"
#include <iostream>
#include <yaml-cpp/yaml.h>
#include <cstdint>
#include <string>
#include <regex>
#include <signal.h>
#include <unistd.h>
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
#include <nlohmann/json.hpp>
#include "kafka_producer.h"

extern KafkaProducer *g_producer;

struct ip_pro_port_rule {
    __u32    target_ip;    
    __u16    target_port;  
    __u8     target_protocol; 
    __u64    rate_bps;      
    __u32    time_scale;    
    __u8     gress : 1;    
    __u8     ip_enable : 1;
    __u8     port_enable : 1;
    __u8     protocol_enable : 5;   
};

struct packet_tuple {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8  protocol;
};

struct message_get {
    __u64 instance_rate_bps; 
    __u64 rate_bps;
    __u64 peak_rate_bps;
    __u64 smoothed_rate_bps;
    struct packet_tuple tuple;
    __u64 timestamp;
};


static struct bpf_object *obj               = nullptr;
static int                 nf_fd_ingress    = -1;
static int                 nf_fd_egress     = -1;
static struct ring_buffer *rb               = nullptr;

static int get_rule(const YAML::Node& module_node)
{
    struct ip_pro_port_rule rule = {0};
    const auto& node = module_node["ip_pro_port_rule"];
    if (!node || node.IsNull()) {
        std::cerr << "[get_rule] 缺少 ip_pro_port_rule 配置\n";
        return -1;
    }

    try {
        rule.target_ip       = parse_ip(node["target_ip"].as<std::string>());
        rule.target_port     = node["target_port"].as<uint16_t>();
        rule.target_protocol = parse_protocol(node["target_protocol"].as<std::string>());
        rule.rate_bps        = parse_rate_bps(node["rate_bps"].as<std::string>());
        rule.time_scale      = parse_time_scale(node["time_scale"].as<std::string>());
        rule.gress           = parse_gress(node["gress"].as<std::string>());
        rule.ip_enable        = parse_flag(node["ip_enable"]);
        rule.port_enable      = parse_flag(node["port_enable"]);
        rule.protocol_enable  = parse_flag(node["protocol_enable"]);
    }
    catch (const std::exception& e) {
        std::cerr << "[get_rule] 配置解析失败: " << e.what() << "\n";
        return -1;
    }

    std::cout 
        << "=== ip_pro_port_rule ===\n"
        << " target_ip         : " << ip_to_string(rule.target_ip)    << "\n"
        << " target_port       : " << rule.target_port                << "\n"
        << " target_protocol   : " << int(rule.target_protocol)       << "\n"
        << " rate_bps          : " << rule.rate_bps << " bps\n"
        << " time_scale        : " << rule.time_scale << " sec\n"
        << " gress             : " << (rule.gress ? "egress" : "ingress") << "\n"
        << " ip_enable         : " << std::boolalpha << bool(rule.ip_enable)       << "\n"
        << " port_enable       : " << std::boolalpha << bool(rule.port_enable)     << "\n"
        << " protocol_enable   : " << std::boolalpha << bool(rule.protocol_enable) << "\n"
        << "========================\n";

    struct bpf_map *map = bpf_object__find_map_by_name(obj, "ip_pro_port_rules");
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
    << "=== ip pro port traffic ===\n" 
    << " src_ip     : " << ip_to_string(e->tuple.src_ip)         << "\n"
    << " dst_ip     : " << ip_to_string(e->tuple.dst_ip)         << "\n"
    << " src_port   : " << ntohs(e->tuple.src_port)              << "\n"
    << " dst_port   : " << ntohs(e->tuple.dst_port)              << "\n"
    << " protocol   : " << protocol_to_string(e->tuple.protocol) << "\n"
    << " instant_rate_bps : " << e->instance_rate_bps / 1024.0 / 1024.0 << " MB/s\n" 
    << " rate_bps         : " << e->rate_bps / 1024.0 / 1024.0 << " MB/s\n"
    << " peak_rate_bps    : " << e->peak_rate_bps / 1024.0 / 1024.0 << " MB/s\n"
    << " smoothed_rate_bps: " << e->smoothed_rate_bps / 1024.0 / 1024.0 << " MB/s\n"
    << " timestamp         : " << format_elapsed_ns(e->timestamp) << "\n"
    << "=====================\n";

    
    nlohmann::json j = {
        {"src_ip", ip_to_string(e->tuple.src_ip)},
        {"dst_ip", ip_to_string(e->tuple.dst_ip)},
        {"src_port", ntohs(e->tuple.src_port)},
        {"dst_port", ntohs(e->tuple.dst_port)},
        {"protocol", protocol_to_string(e->tuple.protocol)},
        {"instant_rate_bps", e->instance_rate_bps / (1024.0 * 1024.0)},
        {"rate_bps", e->rate_bps / (1024.0 * 1024.0)},
        {"peak_rate_bps", e->peak_rate_bps / (1024.0 * 1024.0)},
        {"smoothed_rate_bps", e->smoothed_rate_bps / (1024.0 * 1024.0)},
        {"timestamp", format_elapsed_ns(e->timestamp)}
    };

    if (g_producer) {
        g_producer->send("", j.dump());
    }

    return 0;
}


static int load_netfilter_module(const YAML::Node& module_node)
{
    if (getuid() != 0) {
        std::cerr << "[netfilter] 错误：需要 root 权限\n";
        return -1;
    }

    obj = bpf_object__open_file("../bpf/build/tc_port.o", nullptr);
    if (!obj || libbpf_get_error(obj)) {
        std::cerr << "[netfilter] 打开 BPF 对象失败\n";
        return -1;
    }
    if (bpf_object__load(obj)) {
        std::cerr << "[netfilter] 加载 BPF 对象失败\n";
        bpf_object__close(obj);
        obj = nullptr;
        return -1;
    }

    if (get_rule(module_node) == false) {
        std::cerr << "[netfilter] 读取配置或更新规则失败\n";
        goto error;
    }

    {
        auto prog = bpf_object__find_program_by_name(obj, "netfilter_hook");
        if (!prog) {
            std::cerr << "[netfilter] 找不到 netfilter_hook 程序\n";
            goto error;
        }
        int prog_fd = bpf_program__fd(prog);
        union bpf_attr attr = {};
        attr.link_create.prog_fd             = prog_fd;
        attr.link_create.attach_type         = BPF_NETFILTER;
        attr.link_create.netfilter.pf        = NFPROTO_IPV4;
        attr.link_create.netfilter.hooknum   = NF_INET_LOCAL_IN;
        attr.link_create.netfilter.priority  = -128;
        nf_fd_ingress = syscall(__NR_bpf, BPF_LINK_CREATE, &attr, sizeof(attr));
        if (nf_fd_ingress < 0) {
            std::cerr << "[netfilter] attach ingress 失败: " << strerror(errno) << "\n";
            goto error;
        }
        attr.link_create.netfilter.hooknum = NF_INET_LOCAL_OUT;
        nf_fd_egress = syscall(__NR_bpf, BPF_LINK_CREATE, &attr, sizeof(attr));
        if (nf_fd_egress < 0) {
            std::cerr << "[netfilter] attach egress 失败: " << strerror(errno) << "\n";
            goto error;
        }
    }

    std::cout << "[netfilter] 成功附加 netfilter 钩子\n";

    {
        auto map = bpf_object__find_map_by_name(obj, "ringbuf");
        int map_fd = bpf_map__fd(map);
        rb = ring_buffer__new(map_fd, handle_event, nullptr, nullptr);
        if (!rb) {
            std::cerr << "[netfilter] 创建 ring buffer 失败\n";
            goto error;
        }
        register_ringbuf(rb);
    }

    std::cout << "[netfilter] 模块加载完成，开始处理事件\n";
    return 0;

error:
    if (nf_fd_ingress >= 0) close(nf_fd_ingress);
    if (nf_fd_egress  >= 0) close(nf_fd_egress);
    if (obj) {
        bpf_object__close(obj);
        obj = nullptr;
    }
    return -1;
}

static void unload_netfilter_module()
{
    if (rb)                ring_buffer__free(rb);
    if (nf_fd_ingress >= 0) close(nf_fd_ingress);
    if (nf_fd_egress  >= 0) close(nf_fd_egress);
    if (obj) {
        bpf_object__close(obj);
        obj = nullptr;
    }
    std::cout << "[netfilter] 模块已卸载\n";
}

static const EbpfModule netfilter_module = {
    "tc_port",   
    "ip_pro_port_module",          // YAML 配置节关键字
    load_netfilter_module,     // 加载接口
    unload_netfilter_module    // 卸载接口
};

__attribute__((constructor))
static void register_netfilter_module()
{
    register_module(&netfilter_module);
}
