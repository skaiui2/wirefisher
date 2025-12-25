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

struct process_rule {
    uint32_t target_pid;
    uint64_t rate_bps;
    uint8_t  gress;
    uint32_t time_scale;
};

struct ProcInfo
{
	__u32 pid;
	char comm[16];
};

struct message_get {
    struct flow_rate_message flow_msg;
    struct ProcInfo proc;
};

static struct bpf_object *obj               = nullptr;
static struct bpf_link   *recvmsg_kprobe    = nullptr;
static struct bpf_link   *sendmsg_kprobe    = nullptr;
static int                 nf_fd_ingress    = -1;
static int                 nf_fd_egress     = -1;
static struct ring_buffer *rb               = nullptr;

static int get_rule(const YAML::Node& module_node)
{
    struct process_rule rule = {0};
    const auto& node = module_node["process_rule"];
    if (!node || node.IsNull()) {
        std::cerr << "[get_rule] 缺少 process_rule 配置\n";
        return -1;
    }

    try {
        rule.target_pid = node["target_pid"].as<uint32_t>();
        rule.rate_bps   = parse_rate_bps(node["rate_bps"].as<std::string>());
        rule.gress      = parse_gress(node["gress"].as<std::string>());
        rule.time_scale = parse_time_scale(node["time_scale"].as<std::string>());
    } catch (const std::exception& e) {
        std::cerr << "[get_rule] 配置解析失败: " << e.what() << "\n";
        return -1;
    }

    std::cout << "PID: " << rule.target_pid << "\n";
    std::cout << "Rate: " << rule.rate_bps << " bps\n";
    std::cout << "Gress: " << node["gress"].as<std::string>() << "\n";
    std::cout << "Time Scale: " << rule.time_scale << " sec\n";

    struct bpf_map *map = bpf_object__find_map_by_name(obj, "process_rules");
	if (!map) {
        std::cout << "NO1" << "\n";
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

std::string get_local_ip_address()
{
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        return "127.0.0.1"; 
    }

    struct sockaddr_in addr = {};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr("8.8.8.8"); 
    addr.sin_port = htons(53);

    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        close(sock);
        return "127.0.0.1";
    }

    socklen_t len = sizeof(addr);
    if (getsockname(sock, (struct sockaddr*)&addr, &len) < 0) {
        close(sock);
        return "127.0.0.1";
    }

    close(sock);

    char ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &addr.sin_addr, ip_str, INET_ADDRSTRLEN);

    return std::string(ip_str);
}

static bool setup_local_ip_map()
{
    struct bpf_map *map = bpf_object__find_map_by_name(obj, "local_ip_map");
    if (!map) {
        std::cerr << "No local_ip_map" << std::endl;
        return false;
    }

    std::string local_ip = get_local_ip_address();
    std::cout << "local IP: " << local_ip << std::endl;

    uint32_t key = 0;
    uint32_t ip_addr = inet_addr(local_ip.c_str());

    int err = bpf_map__update_elem(map, &key, sizeof(key), &ip_addr, sizeof(ip_addr), BPF_ANY);
    if (err) {
        std::cerr << "error" << err << std::endl;
        return false;
    }

    std::cout << "set local ip to BPF map" << std::endl;
    return true;
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
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


static int load_netfilter_module(const YAML::Node& module_node)
{
    if (getuid() != 0) {
        std::cerr << "[netfilter] 错误：需要 root 权限\n";
        return -1;
    }

    obj = bpf_object__open_file("../bpf/build/tc_process.o", nullptr);
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

    {
        auto prog = bpf_object__find_program_by_name(obj, "security_socket_recvmsg");
        if (prog)
            recvmsg_kprobe = bpf_program__attach_kprobe(prog, false, "security_socket_recvmsg");
        if (!recvmsg_kprobe) {
            std::cerr << "[netfilter] attach recvmsg kprobe 失败\n";
            goto error;
        }
    }

    {
        auto prog = bpf_object__find_program_by_name(obj, "security_socket_sendmsg");
        if (prog)
            sendmsg_kprobe = bpf_program__attach_kprobe(prog, false, "security_socket_sendmsg");
        if (!sendmsg_kprobe) {
            std::cerr << "[netfilter] attach sendmsg kprobe 失败\n";
            goto error;
        }
    }

    if (get_rule(module_node) == false) {
        std::cerr << "[netfilter] 读取配置或更新规则失败\n";
        goto error;
    }

    if (!setup_local_ip_map()) {
        std::cerr << "[netfilter] setup_local_ip_map 失败\n";
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

    std::cout << "[netfilter] 成功附加 kprobe 和 netfilter 钩子\n";

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
    if (recvmsg_kprobe)  bpf_link__destroy(recvmsg_kprobe);
    if (sendmsg_kprobe)  bpf_link__destroy(sendmsg_kprobe);
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
    if (recvmsg_kprobe)    bpf_link__destroy(recvmsg_kprobe);
    if (sendmsg_kprobe)    bpf_link__destroy(sendmsg_kprobe);
    if (nf_fd_ingress >= 0) close(nf_fd_ingress);
    if (nf_fd_egress  >= 0) close(nf_fd_egress);
    if (obj) {
        bpf_object__close(obj);
        obj = nullptr;
    }
    std::cout << "[netfilter] 模块已卸载\n";
}

// 构造模块描述并自动注册到全局链
static const EbpfModule netfilter_module = {
    "tc_process",   
    "process_module",          // YAML 配置节关键字
    load_netfilter_module,     // 加载接口
    unload_netfilter_module    // 卸载接口
};

__attribute__((constructor))
static void register_netfilter_module()
{
    register_module(&netfilter_module);
}
