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
    struct packet_tuple network_tuple;
    __u64    rate_bps;      
    __u32    time_scale;  
    __u8     only_watch : 1;  
    __u8     gress : 1;    
    __u8     src_ip_enable : 1;
    __u8     dst_ip_enable : 1;
    __u8     src_port_enable : 1;
    __u8     dst_port_enable : 1; 
    __u8     protocol_enable : 2;  
};

struct message_get {
    struct flow_rate_message flow_msg;
    struct packet_tuple tuple;
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
        rule.only_watch = parse_flag(node["only_watch"]);
        rule.network_tuple.src = parse_ip(node["src_ip"].as<std::string>());
        rule.network_tuple.src_port = node["src_port"].as<uint16_t>();
        rule.network_tuple.dst = parse_ip(node["dst_ip"].as<std::string>());
        rule.network_tuple.dst_port = node["dst_port"].as<uint16_t>();
        rule.network_tuple.protocol = parse_protocol(node["protocol"].as<std::string>());
        rule.rate_bps        = parse_rate_bps(node["rate_bps"].as<std::string>());
        rule.time_scale      = parse_time_scale(node["time_scale"].as<std::string>());
        rule.gress           = parse_gress(node["gress"].as<std::string>());
        rule.src_ip_enable   = parse_flag(node["src_ip_enable"]);
        rule.dst_ip_enable   = parse_flag(node["dst_ip_enable"]);
        rule.src_port_enable = parse_flag(node["src_port_enable"]);
        rule.dst_port_enable = parse_flag(node["dst_port_enable"]);
        rule.protocol_enable  = parse_flag(node["protocol_enable"]);
    }
    catch (const std::exception& e) {
        std::cerr << "[get_rule] 配置解析失败: " << e.what() << "\n";
        return -1;
    }

    std::cout 
        << "=== ip_pro_port_rule ===\n"
        << " network_tuple.src_ip         : " << ip_to_string(rule.network_tuple.src)    << "\n"
        << " network_tuple.dst_ip         : " << ip_to_string(rule.network_tuple.dst)    << "\n"
        << " network_tuple.src_port       : " << rule.network_tuple.src_port                << "\n"
        << " network_tuple.dst_port       : " << rule.network_tuple.dst_port                << "\n"
        << " network_tuple.protocol   : " << int(rule.network_tuple.protocol)       << "\n"
        << " rate_bps          : " << rule.rate_bps << " bps\n"
        << " time_scale        : " << rule.time_scale << " sec\n"
        << " gress             : " << (rule.gress ? "egress" : "ingress") << "\n"
        << " src_ip_enable         : " << std::boolalpha << bool(rule.src_ip_enable)       << "\n"
        << " dst_ip_enable         : " << std::boolalpha << bool(rule.dst_ip_enable)       << "\n"
        << " src_port_enable       : " << std::boolalpha << bool(rule.src_port_enable)     << "\n"
        << " dst_port_enable       : " << std::boolalpha << bool(rule.dst_port_enable)     << "\n"
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
    if (data_sz != sizeof(message_get)) {
        std::cerr << "数据大小不匹配: " << data_sz << " (期望 " << sizeof(message_get) << ")\n";
        return 0;
    }

    auto* e = static_cast<const message_get*>(data);

    std::cout << std::fixed << std::setprecision(2) 
    << "=== ip pro port traffic ===\n" 
    << " src_ip     : " << ip_to_string(e->tuple.src)         << "\n"
    << " dst_ip     : " << ip_to_string(e->tuple.dst)         << "\n"
    << " src_port   : " << e->tuple.src_port              << "\n"
    << " dst_port   : " << e->tuple.dst_port              << "\n"
    << " protocol   : " << protocol_to_string(e->tuple.protocol) << "\n"
    << " instant_rate_bps : " << e->flow_msg.instance_rate_bps / 1024.0 / 1024.0 << " MB/s\n" 
    << " rate_bps         : " << e->flow_msg.rate_bps / 1024.0 / 1024.0 << " MB/s\n"
    << " peak_rate_bps    : " << e->flow_msg.peak_rate_bps / 1024.0 / 1024.0 << " MB/s\n"
    << " smoothed_rate_bps: " << e->flow_msg.smooth_rate_bps / 1024.0 / 1024.0 << " MB/s\n"
    << " timestamp         : " << format_elapsed_ns(e->flow_msg.timestamp) << "\n"
    << "=====================\n";

    
    nlohmann::json j = {
        {"src_ip", ip_to_string(e->tuple.src)},
        {"dst_ip", ip_to_string(e->tuple.dst)},
        {"src_port", ntohs(e->tuple.src_port)},
        {"dst_port", ntohs(e->tuple.dst_port)},
        {"protocol", protocol_to_string(e->tuple.protocol)},
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
