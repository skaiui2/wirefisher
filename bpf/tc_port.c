#include "common.h"

char __license[] SEC("license") = "GPL";

#define NF_INET_LOCAL_IN     1
#define NF_INET_LOCAL_OUT    3

#define NF_ACCEPT 1
#define NF_DROP   0

#define ENABLE 1
#define DISABLE 0

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

struct global_stats {
    __u64 total_bytes;
    __u64 total_packets;
    __u64 dropped_bytes;
    __u64 dropped_packets;
    __u64 last_update_ns;
    __u64 current_rate_bps;
    __u64 peak_rate_bps;
    __u64 smoothed_rate_bps;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} ringbuf SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key,  __u32);              
    __type(value, struct ip_pro_port_rule);
    __uint(max_entries, 1024);
} ip_pro_port_rules SEC(".maps");

// Token bucket mapping - using IP + protocol + port as key
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key,  __u64);              
    __type(value, struct rate_bucket);
    __uint(max_entries, 1024);
} buckets SEC(".maps");

// Global traffic statistics map
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key,  __u32);           
    __type(value, struct global_stats);
    __uint(max_entries, 1);
} global_stats_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key,  __u16);               // Port number
    __type(value, struct global_stats);
    __uint(max_entries, 10000);
} port_stats_map SEC(".maps");

static __inline __u64 now_ns(void) 
{
    return bpf_ktime_get_ns();
}

static struct udphdr *udp_hdr(struct sk_buff *skb, u32 offset)
{
    struct bpf_dynptr ptr;
    struct udphdr udph = {};

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
    struct tcphdr tcph = {};

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
    struct iphdr iph = {};

    if (skb->len <= 20) {
        return NULL;
    }

    if (bpf_dynptr_from_skb((struct __sk_buff *)skb, 0, &ptr)) {
        return NULL;
    }

    return bpf_dynptr_slice(&ptr, 0, &iph, sizeof(iph));
}

static __inline bool parse_sk_buff(struct sk_buff *skb, __u8 direction,
                                          struct packet_tuple *tuple)
{
    if (!skb || !tuple) {
        return false;
    }

    if (skb->len < 28) {
        return false;
    }

    struct iphdr *iph = ip_hdr(skb);
    if (!iph) {
        return false;
    }

    if (iph->version != 4) {
        return false;
    }

    __u32 iphl = iph->ihl * 4;
    if (iph->ihl < 5 || skb->len <= iphl) {
        return false;
    }

    tuple->src_ip = bpf_ntohl(iph->saddr);
    tuple->dst_ip = bpf_ntohl(iph->daddr);
    tuple->protocol = iph->protocol;

    if (iph->protocol == IPPROTO_UDP) {
        if (skb->len < iphl + sizeof(struct udphdr)) {
            return false;
        }

        struct udphdr *udph = udp_hdr(skb, iphl);
        if (!udph) {
            return false;
        }

        tuple->src_port = bpf_ntohs(udph->source);
        tuple->dst_port = bpf_ntohs(udph->dest);
    } else if (iph->protocol == IPPROTO_TCP) {
        if (skb->len < iphl + sizeof(struct tcphdr)) {
            return false;
        }

        struct tcphdr *tcph = tcp_hdr(skb, iphl);
        if (!tcph) {
            return false;
        }

        tuple->src_port = bpf_ntohs(tcph->source);
        tuple->dst_port = bpf_ntohs(tcph->dest);
    } else {
        tuple->src_port = 0;
        tuple->dst_port = 0;
    }

    return true;
}

static int netfilter_handle(struct bpf_nf_ctx *ctx)
{
    struct ip_pro_port_rule *rule;
    __u32 rule_key = 0;
    struct packet_tuple tuple = {0};

    if (!ctx || !ctx->skb) {
        return NF_ACCEPT;
    }

    __u8 direction = INGRESS;

    if (!parse_sk_buff(ctx->skb, direction, &tuple)) {
        return NF_ACCEPT; 
    }

    rule = bpf_map_lookup_elem(&ip_pro_port_rules, &rule_key);
    if (!rule) {
        return NF_ACCEPT;
    }

    if (rule->ip_enable == ENABLE && rule->target_ip != tuple.dst_ip) {
        return NF_ACCEPT;
    }

    if (rule->port_enable == ENABLE && rule->target_port != tuple.dst_port) {
        return NF_ACCEPT;
    }

    if (rule->protocol_enable == ENABLE && rule->target_protocol != tuple.protocol) {
        return NF_ACCEPT;
    }

    __u64 bucket_key;
    if (rule->ip_enable == DISABLE && rule->port_enable == DISABLE && rule->protocol_enable == DISABLE) {
        bucket_key = 0;
    } else {
        bucket_key = ((__u64)tuple.dst_ip << 16) | tuple.dst_port | tuple.protocol;
    }
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

SEC("netfilter")
int netfilter_hook(struct bpf_nf_ctx *ctx)
{
    return netfilter_handle(ctx);
}