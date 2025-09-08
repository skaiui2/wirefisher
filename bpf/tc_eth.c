#include "common.h"

char __license[] SEC("license") = "GPL";

#define TC_ACT_OK 0
#define TC_ACT_SHOT 2

struct eth_rule {
    __u64    rate_bps;      
    __u32    time_scale;    
    __u8     gress;       
};

struct message_get {
    __u64 instance_rate_bps; 
    __u64 rate_bps;
    __u64 peak_rate_bps;
    __u64 smoothed_rate_bps;
    __u64    timestamp;
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
	e->timestamp = start_to_now_ns();

	bpf_ringbuf_submit(e, 0);
}


static __inline bool parse_ethernet_header(struct __sk_buff *ctx, void *data, void *data_end,
                                         __u8 *src_mac, __u8 *dst_mac, __u16 *eth_type) 
{
    if (data + 14 > data_end) {
        return false;
    }

    struct ethhdr *eth = (struct ethhdr *)data;

    #pragma unroll
    for (int i = 0; i < 6; i++) {
        src_mac[i] = eth->h_source[i];
    }

    #pragma unroll
    for (int i = 0; i < 6; i++) {
        dst_mac[i] = eth->h_dest[i];
    }

    *eth_type = bpf_ntohs(eth->h_proto);

    return true;
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

    __u64 now = bpf_ktime_get_ns();
    __u32 flow_key = 1;
    struct flow_rate_info *info = bpf_map_lookup_elem(&flow_rate_stats, &flow_key);
    if (!info) {
        struct flow_rate_info new_flow = {
            .window_start_ns = now,
            .total_bytes = ctx->len,
            .packet_bytes = ctx->len,
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
        update_flow_rate(info, ctx->len);
        mes.rate_bps = info->rate_bps;
        mes.instance_rate_bps = info->rate_bps;
        mes.peak_rate_bps = info->peak_rate_bps;
        mes.smoothed_rate_bps = info->smooth_rate_bps;
    }

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
