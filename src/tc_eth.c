#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

char __license[] SEC("license") = "GPL";

#define EGRESS   1
#define INGRESS  0

struct flow_rate_info 
{
    __u64 window_start_ns;   
    __u64 total_packets;     
    __u64 total_bytes;    
    __u64 rate_bps;       
    __u64 peak_rate_bps;    
    __u64 smooth_rate_bps;       
};

struct traffic_rule 
{
    __u64 rate_bps;   
    __u8  gress;      
    __u32 time_scale;  
};

struct rate_bucket 
{
    __u64    ts_ns;  
    __u64 tokens;      
};

struct 
{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} ringbuf SEC(".maps");

struct 
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(__u32));     
    __uint(value_size, sizeof(struct flow_rate_info));
    __uint(max_entries, 1);      
} flow_rate_stats SEC(".maps");

struct 
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(struct traffic_rule));
    __uint(max_entries, 1);
} traffic_rules SEC(".maps");

struct 
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(struct rate_bucket));
    __uint(max_entries, 1024);
} buckets SEC(".maps");

#define NSEC_PER_SEC 1000000000ull

#define TC_ACT_OK 0
#define TC_ACT_SHOT 2

#define ACCEPT TC_ACT_OK
#define DROP TC_ACT_SHOT

static __inline __u64 now_ns(void) 
{
    return bpf_ktime_get_ns();
}

static __inline bool parse_ethernet_header(struct __sk_buff *ctx, void *data, void *data_end,
                                         __u8 *src_mac, __u8 *dst_mac, __u16 *eth_type) 
{
    if (data + 14 > data_end) {
        return false;
    }

    struct ethhdr *eth = data;

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

static __inline void update_flow_rate(struct flow_rate_info *flow_info,__u64 now, __u32 packet_size) 
{
    
    flow_info->rate_bps = (flow_info->total_bytes * NSEC_PER_SEC) / (now - flow_info->window_start_ns);
    if (flow_info->rate_bps > flow_info->peak_rate_bps) {
        flow_info->peak_rate_bps = flow_info->rate_bps;
    }

    if (flow_info->smooth_rate_bps != 0) {
        flow_info->smooth_rate_bps = (flow_info->smooth_rate_bps - (flow_info->smooth_rate_bps >> 3)) + (flow_info->rate_bps  >> 3);
    } else {
        flow_info->smooth_rate_bps = flow_info->rate_bps;
    }
}


static __inline int rate_limit_check(__u64 bucket_key, __u32 rate_bps, __u32 time_scale,__u32 packet_len)
{
    __u64 now = now_ns();
    __u64 delta_ns;
    struct rate_bucket *b;
    
    __u64 max_bucket = (rate_bps * time_scale) >> 2;

    b = bpf_map_lookup_elem(&buckets, &bucket_key);
    if (!b) {
        struct rate_bucket init = { 
            .ts_ns = now, 
            .tokens = max_bucket
        };
        bpf_map_update_elem(&buckets, &bucket_key, &init, BPF_ANY);
        b = bpf_map_lookup_elem(&buckets, &bucket_key);
        if (!b) {
            return ACCEPT;
        }
    }

    delta_ns = now - b->ts_ns;
    b->tokens += (delta_ns * rate_bps) / NSEC_PER_SEC;
    if (b->tokens > max_bucket) {
        b->tokens = max_bucket;
    }

    b->ts_ns = now;

    if (b->tokens < packet_len) {
        return DROP;
    }

    b->tokens -= packet_len;

    return ACCEPT;
}

static int tc_handle(struct __sk_buff *ctx, int gress)
{
    __u32 bucket_key = gress; 
    __u32 rule_key = 0;
    struct traffic_rule *rule = bpf_map_lookup_elem(&traffic_rules, &rule_key);
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
            .total_packets = 1,
            .total_bytes = ctx->len,
            .rate_bps = 0,
            .peak_rate_bps = 0
        };
        bpf_map_update_elem(&flow_rate_stats, &flow_key, &new_flow, BPF_ANY);
    }
    update_flow_rate(info, now, ctx->len);

    return rate_limit_check(bucket_key, rule->rate_bps, rule->time_scale, ctx->len);
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
