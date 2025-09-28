#include "common.h"
#include <bpf/bpf_core_read.h>

char __license[] SEC("license") = "GPL";

#define NF_INET_LOCAL_IN     1
#define NF_INET_LOCAL_OUT    3

#define NF_ACCEPT 1
#define NF_DROP   0


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

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} ringbuf SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(__u32));     
    __uint(value_size, sizeof(struct flow_rate_info));
    __uint(max_entries, 1);      
} flow_rate_stats SEC(".maps");

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


static __inline void send_message(struct message_get *mes)
{
	struct message_get *e;

	e = bpf_ringbuf_reserve(&ringbuf, sizeof(*e), 0);
	if (!e) {
		return;
	}
    *e = *mes;

	struct packet_tuple *tuple = &(e->tuple);
    tuple->src_ip = mes->tuple.src_ip;
    tuple->dst_ip = mes->tuple.dst_ip;
    tuple->src_port = mes->tuple.src_port;        
    tuple->dst_port = mes->tuple.dst_port;
    tuple->protocol = mes->tuple.protocol;
    e->timestamp = bpf_ktime_get_ns();

	bpf_ringbuf_submit(e, 0);
}

static __inline bool parse_sk_buff(struct sk_buff *skb, struct packet_tuple *tuple)
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
    struct message_get mes = {0};
    struct packet_tuple *tuple = &(mes.tuple);

    if (!ctx || !ctx->skb) {
        return NF_ACCEPT;
    }

    __u32 hook_state = BPF_CORE_READ(ctx->state, hook);

    rule = bpf_map_lookup_elem(&ip_pro_port_rules, &rule_key);
    if (!rule) {
        return NF_ACCEPT;
    }

    if (rule->gress == EGRESS && hook_state != NF_INET_LOCAL_OUT) {
        return NF_ACCEPT;
    }

    if (rule->gress == INGRESS && hook_state != NF_INET_LOCAL_IN) {
        return NF_ACCEPT;
    }

    if (!parse_sk_buff(ctx->skb, tuple)) {
        return NF_ACCEPT; 
    }

    if (rule->ip_enable == true && rule->target_ip != tuple->dst_ip) {
        return NF_ACCEPT;
    }

    if (rule->port_enable == true && rule->target_port != tuple->dst_port) {
        return NF_ACCEPT;
    }

    if (rule->protocol_enable == true && rule->target_protocol != tuple->protocol) {
        return NF_ACCEPT;
    }
    
    __u64 now = bpf_ktime_get_ns();
    __u32 flow_key = 1;
    struct flow_rate_info *info = bpf_map_lookup_elem(&flow_rate_stats, &flow_key);
    if (!info) {
        struct flow_rate_info new_flow = {
            .window_start_ns = now,
            .total_bytes = ctx->skb->len,
            .packet_bytes = ctx->skb->len,
            .last_ns = now,
            .instance_rate_bps = 0,
            .rate_bps = 0,
            .peak_rate_bps = 0,
            .smooth_rate_bps = 0
        };
        bpf_map_update_elem(&flow_rate_stats, &flow_key, &new_flow, BPF_ANY); 
    }
    info = bpf_map_lookup_elem(&flow_rate_stats, &flow_key);
    if (info) {
        update_flow_rate(info, ctx->skb->len);
        mes.rate_bps = info->rate_bps;
        mes.instance_rate_bps = info->rate_bps;
        mes.peak_rate_bps = info->peak_rate_bps;
        mes.smoothed_rate_bps = info->smooth_rate_bps;
    }

    send_message(&mes);

    __u64 bucket_key;
    if (rule->ip_enable == false && rule->port_enable == false && rule->protocol_enable == false) {
        bucket_key = 0;
    } else {
        bucket_key = ((__u64)tuple->dst_ip << 16) | tuple->dst_port | tuple->protocol;
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