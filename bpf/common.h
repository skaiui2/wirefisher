#ifndef COMMON_H
#define COMMON_H
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

#define NSEC_PER_SEC 1000000000ull

#define ETH_P_IP 0x0800
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17

#define ACCEPT 1
#define DROP   0

#define EGRESS   1
#define INGRESS  0

struct rate_bucket {
    __u64    ts_ns;        
    __u64    tokens;      
};

struct rate_limit {
    __u64 *bucket_key;
    __u32 rate_bps;
    __u32 time_scale;
    __u32 packet_len;
    void *buckets;
};


struct flow_rate_info {
    __u64 window_start_ns;
    __u64 last_ns;   
    __u64 total_bytes;
    __u64 packet_bytes;     
    __u64 rate_bps;      
    __u64 instance_rate_bps;
    __u64 peak_rate_bps;    
    __u64 smooth_rate_bps;       
};

static __inline __u64 start_to_now_ns(void) 
{
    return bpf_ktime_get_ns();
}

static __always_inline int rate_limit_check(struct rate_limit *rate)
{
    __u64 now = bpf_ktime_get_ns();
    __u64 delta_ns;
    struct rate_bucket *b;
    
    __u64 max_bucket = (rate->rate_bps * rate->time_scale) >> 2;

    b = bpf_map_lookup_elem(rate->buckets, rate->bucket_key);
    if (!b) {
        struct rate_bucket init = { 
            .ts_ns = now, 
            .tokens = max_bucket
        };
        bpf_map_update_elem(rate->buckets, rate->bucket_key, &init, 0);
        b = bpf_map_lookup_elem(rate->buckets, rate->bucket_key);
        if (!b) {
            return ACCEPT;
        }
    }

    delta_ns = now - b->ts_ns;
    b->tokens += (delta_ns * rate->rate_bps) / NSEC_PER_SEC;
    if (b->tokens > max_bucket) {
        b->tokens = max_bucket;
    }

    b->ts_ns = now;

    if (b->tokens < rate->packet_len) {
        return DROP;
    }

    b->tokens -= rate->packet_len;

    return ACCEPT;
}


static __inline void update_flow_rate(struct flow_rate_info *flow_info, __u32 packet_size) 
{
    __u64 now = start_to_now_ns();
    flow_info->total_bytes += packet_size;
    flow_info->rate_bps = (flow_info->total_bytes * NSEC_PER_SEC) / (now - flow_info->window_start_ns);
    if (now - flow_info->last_ns >= NSEC_PER_SEC) {
        flow_info->instance_rate_bps = (flow_info->packet_bytes * NSEC_PER_SEC) / (now - flow_info->last_ns);
        if (flow_info->instance_rate_bps > flow_info->peak_rate_bps) {
            flow_info->peak_rate_bps = flow_info->instance_rate_bps;
        }

        if (flow_info->smooth_rate_bps != 0) {
            flow_info->smooth_rate_bps = (flow_info->smooth_rate_bps - (flow_info->smooth_rate_bps >> 3)) + (flow_info->instance_rate_bps  >> 3);
        } else {
            flow_info->smooth_rate_bps = flow_info->instance_rate_bps;
        }
        flow_info->last_ns = now;
        flow_info->packet_bytes = packet_size;
    } else {
        flow_info->packet_bytes += packet_size;
    }
}


#endif
