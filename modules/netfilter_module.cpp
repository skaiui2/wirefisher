#include "registry.h"
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
    struct ProcInfo proc;   
};

static struct bpf_object *obj               = nullptr;
static struct bpf_link   *recvmsg_kprobe    = nullptr;
static struct bpf_link   *sendmsg_kprobe    = nullptr;
static int                 nf_fd_ingress    = -1;
static int                 nf_fd_egress     = -1;
static struct ring_buffer *rb               = nullptr;
static struct process_rule rule = {0};

uint64_t parse_rate_bps(const std::string& rate_str) {
    std::regex pattern(R"((\d+)([KMG]?))");
    std::smatch match;
    if (std::regex_match(rate_str, match, pattern)) {
        uint64_t base = std::stoull(match[1].str());
        std::string unit = match[2].str();
        if (unit == "K") return base * 1024;
        if (unit == "M") return base * 1024 * 1024;
        if (unit == "G") return base * 1024 * 1024 * 1024;
        return base;
    }
    throw std::runtime_error("Invalid rate_bps format");
}

uint32_t parse_time_scale(const std::string& time_str) {
    std::regex pattern(R"((\d+)(s|ms|m))");
    std::smatch match;
    if (std::regex_match(time_str, match, pattern)) {
        uint32_t base = std::stoul(match[1].str());
        std::string unit = match[2].str();
        if (unit == "ms") return base / 1000;
        if (unit == "m")  return base * 60;
        return base; // "s"
    }
    throw std::runtime_error("Invalid time_scale format");
}

uint8_t parse_gress(const std::string& gress_str) {
    if (gress_str == "ingress") return 0;
    if (gress_str == "engress") return 1;
    throw std::runtime_error("Invalid gress value");
}


static int get_rule(process_rule *rule)
{
    YAML::Node config = YAML::LoadFile("../config/config.yaml");
    const auto& node = config["process_rule"];

    rule->target_pid = node["target_pid"].as<uint32_t>();
    rule->rate_bps   = parse_rate_bps(node["rate_bps"].as<std::string>());
    rule->gress      = parse_gress(node["gress"].as<std::string>());
    rule->time_scale = parse_time_scale(node["time_scale"].as<std::string>());

    std::cout << "PID: " << rule->target_pid << "\n";
    std::cout << "Rate: " << rule->rate_bps << " bps\n";
    std::cout << "Gress: " << node["gress"].as<std::string>() << "\n";
    std::cout << "Time Scale: " << rule->time_scale << " sec\n";

    struct bpf_map *map = bpf_object__find_map_by_name(obj, "process_rules");
	if (!map) {
        std::cout << "NO1" << "\n";
        return false;
	}

	uint32_t key = 0;

	int err = bpf_map__update_elem(map,&key, sizeof(key), &rule, sizeof(*rule), BPF_ANY);
	if (err) {
        std::cout << "NO3" << "\n";
        return false;
	}
    return true;
}

std::string get_local_ip_address()
{
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0)
    {
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
    if (data_sz != sizeof(struct message_get)) {
        return 0;
    }

    const struct message_get *e = static_cast<const struct message_get*>(data);
    std::cout << "PID=" << e->proc.pid << " (" << e->proc.comm << ")" << std::endl;
    return 0;
}


static int load_netfilter_module()
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

    if (get_rule(&rule) == false) {
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
    }

    std::cout << "[netfilter] 模块加载完成，开始处理事件\n";
    return 0;

error:
    // 若加载流程中任一步失败，执行卸载清理
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

// 卸载函数：反向清理所有资源
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
    load_netfilter_module,     // 加载接口
    unload_netfilter_module    // 卸载接口
};

__attribute__((constructor))
static void register_netfilter_module()
{
    register_module(&netfilter_module);
}


void out()
{
    int err = ring_buffer__poll(rb, 100);
        if (err == -EINTR)
        {
            
        }
        if (err < 0)
        {
            std::cerr << "轮询环形缓冲区错误: " << err << std::endl;
            
        }
}