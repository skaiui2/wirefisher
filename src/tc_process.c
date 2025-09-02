#define __TARGET_ARCH_x86
#include "common.h"
#include <bpf/bpf_core_read.h>

char __license[] SEC("license") = "GPL";

#define EGRESS   1
#define INGRESS  0

#define NF_INET_PRE_ROUTING  0
#define NF_INET_LOCAL_IN     1
#define NF_INET_FORWARD      2
#define NF_INET_LOCAL_OUT    3
#define NF_INET_POST_ROUTING 4

#define NF_DROP    0   /* 丢弃数据包：包被丢弃，不再进行后续协议栈或其他 hook 处理 */
#define NF_ACCEPT  1   /* 接收数据包：允许继续正常传递，或进入下一个 hook/协议栈 */
#define NF_STOLEN  2   /* 包已被 hook “接管”：hook 函数已自行处理该包，不再做其他处理 */
#define NF_QUEUE   3   /* 将包排队交给 userspace：通过 netlink 送到 userspace（nfnetlink_queue） */
#define NF_REPEAT  4   /* 重复调用本 hook：在同一样点重新遍历所有注册的 hook 函数 */
#define NF_STOP    5   /* 停止后续 hook 调用（已弃用，仅为 userspace nf_queue 兼容） */

struct ProcInfo
{
	__u32 pid;
	char comm[16];
};

struct net_group {
    __u32 ip;     
    __u16 port;     
    __u8  protocol; 
};

struct process_rule {
    __u32    target_pid;   
    __u64    rate_bps;     
    __u8     gress;        
    __u32    time_scale;  
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, struct sock *);
	__type(value, struct ProcInfo);
	__uint(max_entries, 20000);
} sock_map SEC(".maps");


struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key,  __u32);              
    __type(value, struct process_rule);
    __uint(max_entries, 1024);
} process_rules SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key,  __u32);               
    __type(value, struct rate_bucket);
    __uint(max_entries, 1024);
} buckets SEC(".maps");


struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, struct net_group);
    __type(value, struct ProcInfo);
    __uint(max_entries, 20000);
} tuple_map SEC(".maps");


struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);              
    __type(value, __u32);         
    __uint(max_entries, 1);
} local_ip_map SEC(".maps");

static struct udphdr *udp_hdr(struct sk_buff *skb, u32 offset)
{
    struct bpf_dynptr ptr;
    struct udphdr *p, udph = {};
    if (skb->len <= offset) {
        return NULL;
    }

    if (bpf_dynptr_from_skb((struct __sk_buff *)skb, 0, &ptr)) {
        return NULL;
    }

    return bpf_dynptr_slice(&ptr, offset, &udph, sizeof(udph));
}

static struct tcphdr *tcp_hdr(struct sk_buff *skb, u32 offset)
{
    struct bpf_dynptr ptr;
    struct tcphdr *p, tcph = {};
    if (skb->len <= offset) {
        return NULL;
    }

    if (bpf_dynptr_from_skb((struct __sk_buff *)skb, 0, &ptr)) {
        return NULL;
    }

    return bpf_dynptr_slice(&ptr, offset, &tcph, sizeof(tcph));
}

static struct iphdr *ip_hdr(struct sk_buff *skb)
{
	struct bpf_dynptr ptr;
	struct iphdr *p, iph = {};

	if (skb->len <= 20) {
		return NULL;
    }

    if (bpf_dynptr_from_skb((struct __sk_buff *)skb, 0, &ptr)) {
        return NULL;
    }

	return bpf_dynptr_slice(&ptr, 0, &iph, sizeof(iph));
}

static __attribute__((noinline)) bool parse_sk_buff(struct sk_buff *skb, __u8 direction,
                         struct net_group *tuple)
{
    struct iphdr *iph;
    struct udphdr *udph;
    struct tcphdr *tcph;
    unsigned int iphl;

    if (skb->len < 28) {
        return false;
    }

    iph = ip_hdr(skb);
    if (!iph) {
        return false;
    }

    if (iph->version != 4) {
        return false;
    }

    iphl = iph->ihl * 4;

    if (iph->ihl < 5) {
        return false;
    }

    if (skb->len <= iphl) {
        return false;
    }

    if (iph->protocol == IPPROTO_UDP) {
        if (skb->len < iphl + sizeof(struct udphdr)) {
            return false;
        }

        udph = udp_hdr(skb, iphl);
        if (!udph) {
            return false;
        }

        tuple->protocol = IPPROTO_UDP;
        if (direction == EGRESS) {
            tuple->ip = bpf_ntohl(iph->saddr);
            tuple->port = bpf_ntohs(udph->source);
        } else { 
            tuple->ip = (iph->daddr);
            tuple->port = (udph->dest);
        }
    } else if (iph->protocol == IPPROTO_TCP) {
        if (skb->len < iphl + sizeof(struct tcphdr)) {
            return false;
        }

        tcph = tcp_hdr(skb, iphl);
        if (!tcph) {
            return false;
        }

        tuple->protocol = IPPROTO_TCP;
        if (direction == EGRESS) {
            tuple->ip = bpf_ntohl(iph->saddr);
            tuple->port = bpf_ntohs(tcph->source);
        } else { 
            tuple->ip = bpf_ntohl(iph->daddr);
            tuple->port = bpf_ntohs(tcph->dest);
        }
    } else {
        return false;
    }

    return true;
}

static void save_sock(struct socket *sock)
{
	struct sock *sk = BPF_CORE_READ(sock, sk);
	if (!sk) return;

	struct ProcInfo proc = {};
	proc.pid = bpf_get_current_pid_tgid() >> 32;
	bpf_get_current_comm(proc.comm, sizeof(proc.comm));

	bpf_map_update_elem(&sock_map, &sk, &proc, BPF_ANY);
}

SEC("kprobe/security_socket_recvmsg")
int BPF_KPROBE(security_socket_recvmsg,
    struct socket *sock, struct msghdr *msg)
{
    save_sock(sock);

    struct sock *sk = BPF_CORE_READ(sock, sk);
    if (sk) {
        __u16 skproto = BPF_CORE_READ(sk, sk_protocol);
        if (skproto != IPPROTO_UDP) {
            return 0;
        }

        __u32 daddr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
        __u16 dport = BPF_CORE_READ(sk, __sk_common.skc_num);

        if (daddr == 0) {
            __u32 key = 0;
            __u32 *local_ip = bpf_map_lookup_elem(&local_ip_map, &key);
            if (local_ip) {
                daddr = bpf_ntohl(*local_ip);
            }
        }

        struct net_group key = { };
        key.ip = bpf_ntohl(daddr);
        key.port = bpf_ntohs(dport);
        key.protocol = IPPROTO_UDP;

        struct ProcInfo proc = {};
        proc.pid = bpf_get_current_pid_tgid() >> 32;
        bpf_get_current_comm(proc.comm, sizeof(proc.comm));
        bpf_map_update_elem(&tuple_map, &key, &proc, BPF_ANY);
    }

    return 0;
}


SEC("kprobe/security_socket_sendmsg")
int BPF_KPROBE(security_socket_sendmsg,
    struct socket *sock)
{
    if (!sock) {
        return 0;
    }

    save_sock(sock); 
    return 0;
}


SEC("netfilter")
int netfilter_hook(struct bpf_nf_ctx *ctx)
{
    struct process_rule *rule;
    __u32 rule_key = 0;

    rule = bpf_map_lookup_elem(&process_rules, &rule_key);

    if (!rule) {
        return NF_ACCEPT;
    }

    if (!ctx || !ctx->skb) {
        return NF_ACCEPT;
    }

    __u32 hook_state = BPF_CORE_READ(ctx->state, hook);

    if (rule->gress == EGRESS && hook_state != NF_INET_LOCAL_OUT) {
        return NF_ACCEPT;
    }

    if (rule->gress == INGRESS && hook_state != NF_INET_LOCAL_IN) {
        return NF_ACCEPT;
    }

    volatile struct sock *pre_sk = BPF_CORE_READ(ctx->skb, sk);

    struct ProcInfo *proc;
    struct net_group key = { };
    int i = parse_sk_buff(ctx->skb, INGRESS, &key);
    if (i == false) {
        return NF_ACCEPT; 
    }

    if (hook_state == NF_INET_LOCAL_IN && key.protocol == IPPROTO_UDP) {
        proc = bpf_map_lookup_elem(&tuple_map, &key);
    } else {
        if (!pre_sk) {
            return NF_ACCEPT;
        }
        struct sock *sk_ptr = (struct sock *)pre_sk;
        proc = bpf_map_lookup_elem(&sock_map, &sk_ptr);
    }

    if (!proc) {
        return NF_ACCEPT;
    }

    __u32 pid = proc->pid;
    if (pid == 0) {
        return NF_ACCEPT;
    }

    if (rule->target_pid != proc->pid) {
        return NF_ACCEPT;
    }

    __u64 bucket_key = proc->pid;
    struct rate_limit rate = {
        .bucket_key = &bucket_key,
        .buckets = &buckets,
        .packet_len = ctx->skb->len,
        .rate_bps = rule->rate_bps,
        .time_scale = rule->time_scale
    };

    if (rate_limit_check(&rate) == ACCEPT) {
        return NF_ACCEPT;
    }
    return NF_DROP;
}
