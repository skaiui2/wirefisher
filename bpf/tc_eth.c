#include "rate_limit.h"
#include "hdr_parse.h"
char __license[] SEC("license") = "GPL";

#define TC_ACT_OK 0
#define TC_ACT_SHOT 2

struct eth_rule {
    __u64    rate_bps;      
    __u32    time_scale;    
    __u8     gress;       
};

struct message_get {
    struct flow_rate_message flow_msg;
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
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(struct eth_rule));
    __uint(max_entries, 1);
} eth_rules SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(__u8));
    __uint(value_size, sizeof(struct rate_bucket));
    __uint(max_entries, 2);
} buckets SEC(".maps");

static __inline void send_message(struct message_get *mes)
{
	struct message_get *e;

	e = bpf_ringbuf_reserve(&ringbuf, sizeof(*e), 0);
	if (!e) {
		return;
	}
    *e = *mes;

	bpf_ringbuf_submit(e, 0);
}

static int tc_handle(struct __sk_buff *ctx, int gress)
{
    struct message_get mes = {0};
    __u64 bucket_key = gress; 
    __u32 rule_key = 0;
    struct eth_rule *rule = bpf_map_lookup_elem(&eth_rules, &rule_key);
    if (!rule || (rule->gress != gress)) {
        return TC_ACT_OK;
    }

    void *data_end = (void *)(__u64)ctx->data_end;
    if (!data_end) {
        return TC_ACT_OK;
    }

    void *data = (void *)(__u64)ctx->data;
    if (!data) {
        return TC_ACT_OK;
    }

    __u8 src_mac[6] = {0};
    __u8 dst_mac[6] = {0};
    __u16 eth_type = 0;

    bool eth_parsed = parse_ethernet_header(ctx, data, data_end, src_mac, dst_mac, &eth_type);
    if (!eth_parsed) {
        return TC_ACT_OK;
    }

    update_flow(&flow_rate_stats, &mes.flow_msg, ctx->len);

    send_message(&mes);

    struct rate_limit rate = {
        .bucket_key = &bucket_key,
        .buckets = &buckets,
        .packet_len = ctx->len,
        .rate_bps = rule->rate_bps,
        .time_scale = rule->time_scale
    };

    if (rate_limit_check(&rate) == ACCEPT) {
        return TC_ACT_OK;
    }
    return TC_ACT_SHOT;
}

SEC("tc")
int tc_egress(struct __sk_buff *ctx)
{
    return tc_handle(ctx, EGRESS);
}

SEC("tc")
int tc_ingress(struct __sk_buff *ctx)
{
    return tc_handle(ctx, INGRESS);
}
