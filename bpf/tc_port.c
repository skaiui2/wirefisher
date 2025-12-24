#include "hdr_parse.h"
#include "rate_limit.h"
#include <bpf/bpf_core_read.h>

char __license[] SEC("license") = "GPL";

#define NF_INET_LOCAL_IN     1
#define NF_INET_LOCAL_OUT    3

#define NF_ACCEPT 1
#define NF_DROP   0

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

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
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

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key,  struct packet_tuple);              
    __type(value, struct rate_bucket);
    __uint(max_entries, 1024);
} buckets SEC(".maps");


static __inline void send_message(struct message_get *mes)
{
	struct message_get *e;

	e = bpf_ringbuf_reserve(&ringbuf, sizeof(*e), 0);
	if (!e) {
		return;
	}
    *e = *mes;

	struct packet_tuple *tuple = &(e->tuple);
    tuple->src = mes->tuple.src;
    tuple->dst = mes->tuple.dst;
    tuple->src_port = mes->tuple.src_port;        
    tuple->dst_port = mes->tuple.dst_port;
    tuple->protocol = mes->tuple.protocol;

	bpf_ringbuf_submit(e, 0);
}

static __always_inline bool match_rule(const struct ip_pro_port_rule *rule,
                                       const struct packet_tuple *tuple)
{
    if (rule->protocol_enable) {
        if (rule->network_tuple.protocol != tuple->protocol)
            return false;
    }

    if (rule->src_port_enable) {
        if (rule->network_tuple.src_port != tuple->src_port)
            return false;
    }

    if (rule->dst_port_enable) {
        if (rule->network_tuple.dst_port != tuple->dst_port)
            return false;
    }

    if (rule->src_ip_enable) {
        if (tuple->src.version == 4) {
            if (rule->network_tuple.src.version != 4)
                return false;
            if (rule->network_tuple.src.v4 != tuple->src.v4)
                return false;
        } else {
            if (rule->network_tuple.src.version != 6)
                return false;
            if (__builtin_memcmp(rule->network_tuple.src.v6,
                                 tuple->src.v6, 16) != 0)
                return false;
        }
    }

    if (rule->dst_ip_enable) {
        if (tuple->dst.version == 4) {
            if (rule->network_tuple.dst.version != 4)
                return false;
            if (rule->network_tuple.dst.v4 != tuple->dst.v4)
                return false;
        } else {
            if (rule->network_tuple.dst.version != 6)
                return false;
            if (__builtin_memcmp(rule->network_tuple.dst.v6,
                                 tuple->dst.v6, 16) != 0)
                return false;
        }
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

    if (!parse_net(ctx->skb, tuple)) {
        return NF_ACCEPT; 
    }

    if (rule->only_watch) {
        send_message(&mes);
        return NF_ACCEPT;
    }

    if (!match_rule(rule, tuple)) {
        return NF_ACCEPT;
    }

    update_flow(&flow_rate_stats, &mes.flow_msg, ctx->skb->len);

    send_message(&mes);

    struct rate_limit rate = {
        .bucket_key = tuple,
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