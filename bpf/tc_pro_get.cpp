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

static struct bpf_object *obj = nullptr;
static struct ring_buffer *rb = nullptr;
static struct bpf_link *recvmsg_kprobe_link = nullptr;
static struct bpf_link *send_kprobe_link = nullptr;

static int netfilter_fd_ingress = -1;
static int netfilter_fd_egress = -1;
static volatile bool running = true;
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

static void sig_handler(int sig)
{
    std::cout << "\nget sig " << sig << ", exiting..." << std::endl;
    running = false;
}

static void get_rule(process_rule *rule)
{
    YAML::Node config = YAML::LoadFile("../config.yaml");
    const auto& node = config["process_rule"];

    rule->target_pid = node["target_pid"].as<uint32_t>();
    rule->rate_bps   = parse_rate_bps(node["rate_bps"].as<std::string>());
    rule->gress      = parse_gress(node["gress"].as<std::string>());
    rule->time_scale = parse_time_scale(node["time_scale"].as<std::string>());

    std::cout << "PID: " << rule->target_pid << "\n";
    std::cout << "Rate: " << rule->rate_bps << " bps\n";
    std::cout << "Gress: " << static_cast<int>(rule->gress) << "\n";
    std::cout << "Time Scale: " << rule->time_scale << " sec\n";

    struct bpf_map *map = bpf_object__find_map_by_name(obj, "process_rules");
	if (!map) {
        std::cout << "NO1" << "\n";
	}

	uint32_t key = 0;

	int err = bpf_map__update_elem(map,&key, sizeof(key), &rule, sizeof(*rule), BPF_ANY);
	if (err) {
        std::cout << "NO3" << "\n";
	}
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

int main()
{
    int err = 0;
    union bpf_attr attr = {};
    int netfilter_fd_ingress = -1;
    int netfilter_fd_egress = -1;
    struct bpf_program *prog = nullptr;
    struct bpf_map *ringbuf_map = nullptr;
    struct bpf_map *map = nullptr;

    if (getuid() != 0) {
        std::cerr << "err: no root!" << std::endl;
        return 1;
    }

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    // Open and load BPF object
    obj = bpf_object__open_file("tc_process.o", NULL);
    if (libbpf_get_error(obj)) {
        std::cerr << "Failed to open tc_process.o" << std::endl;
        return 1;
    }
    if (bpf_object__load(obj)) {
        std::cerr << "Failed to load tc_process.o" << std::endl;
        bpf_object__close(obj);
        return 1;
    }

    prog = bpf_object__find_program_by_name(obj, "security_socket_recvmsg");
    if (prog) recvmsg_kprobe_link = bpf_program__attach_kprobe(prog, false, "security_socket_recvmsg");
    else { err = -1; goto cleanup; }
    prog = bpf_object__find_program_by_name(obj, "security_socket_sendmsg");
    if (prog) send_kprobe_link = bpf_program__attach_kprobe(prog, false, "security_socket_sendmsg");
    else { err = -1; goto cleanup; }
    
    get_rule(&rule);

    if (!setup_local_ip_map())
    {
        goto cleanup;
    }

    // Attach netfilter program for both directions (via BPF_LINK_CREATE)
    // Attach to ingress hook (NF_INET_LOCAL_IN)
    prog = bpf_object__find_program_by_name(obj, "netfilter_hook");
    attr.link_create.prog_fd = prog ? bpf_program__fd(prog) : -1;
    attr.link_create.attach_type = BPF_NETFILTER;
    attr.link_create.netfilter.pf = NFPROTO_IPV4;
    attr.link_create.netfilter.hooknum = NF_INET_LOCAL_IN;
    attr.link_create.netfilter.priority = -128;

    netfilter_fd_ingress = syscall(__NR_bpf, BPF_LINK_CREATE, &attr, sizeof(attr));
    if (netfilter_fd_ingress < 0)
    {
        std::cerr << "附加netfilter ingress程序失败: " << strerror(errno) << std::endl;
        goto cleanup;
    }

    // Attach to egress hook (NF_INET_LOCAL_OUT)
    attr.link_create.netfilter.hooknum = NF_INET_LOCAL_OUT;
    netfilter_fd_egress = syscall(__NR_bpf, BPF_LINK_CREATE, &attr, sizeof(attr));
    if (netfilter_fd_egress < 0)
    {
        std::cerr << "附加netfilter egress程序失败: " << strerror(errno) << std::endl;
        close(netfilter_fd_ingress);
        goto cleanup;
    }

    // Save FDs to globals
    netfilter_fd_ingress = netfilter_fd_ingress;
    netfilter_fd_egress = netfilter_fd_egress;

    std::cout << "成功附加netfilter程序，处理两个方向的流量" << std::endl;

    std::cout << "=== 流量控制配置 ===" << std::endl;
    std::cout << "目标进程PID: " << rule.target_pid << std::endl;
    std::cout << "匹配方向: " << (rule.gress ? "发送(EGRESS)" : "接收(INGRESS)") << std::endl;
    std::cout << "带宽限制: " << rule.rate_bps << " B/s (" 
              << (rule.rate_bps / 1024.0 / 1024.0) << " MB/s)" << std::endl;
    std::cout << "时间刻度: " << rule.time_scale << "秒" << std::endl;
    std::cout << "===================" << std::endl;

    // Create ring buffer for events
    ringbuf_map = bpf_object__find_map_by_name(obj, "ringbuf");
    rb = ring_buffer__new(bpf_map__fd(ringbuf_map), handle_event, nullptr, nullptr);
    if (!rb) {
        std::cerr << "创建环形缓冲区失败" << std::endl;
        err = -1;
        goto cleanup;
    }

    std::cout << "开始监控进程流量..." << std::endl;
    std::cout << "按 Ctrl+C 停止监控" << std::endl;
    std::cout << "===================" << std::endl;

    // interrupted by signal
    while (running)
    {
        err = ring_buffer__poll(rb, 100);
        if (err == -EINTR)
        {
            continue; 
        }
        if (err < 0)
        {
            std::cerr << "轮询环形缓冲区错误: " << err << std::endl;
            break;
        }
    }

    // Netfilter links will be destroyed on exit
    std::cout << "netfilter程序将在程序退出时自动卸载" << std::endl;

cleanup:

    // Detach recvmsg kprobe
    if (recvmsg_kprobe_link) {
        bpf_link__destroy(recvmsg_kprobe_link);
    }

    // Detach sendmsg kprobe
    if (send_kprobe_link) {
        bpf_link__destroy(send_kprobe_link);
    }

    // Close netfilter link FDs
    if (netfilter_fd_ingress >= 0) {
        close(netfilter_fd_ingress);
    }
    if (netfilter_fd_egress >= 0) {
        close(netfilter_fd_egress);
    }

    if (rb) {
        ring_buffer__free(rb);
    }

    if (obj) {
        bpf_object__close(obj);
    }

    return -err;
}