#ifndef RATE_LIMIT_H
#define RATE_LIMIT_H

#include "common.h"

struct rate_bucket {
    __u64    ts_ns;        
    __u64    tokens;      
};

struct rate_limit {
    void *bucket_key;
    __u32 rate_bps;
    __u32 time_scale;
    __u32 packet_len;
    void *buckets;
};


struct flow_rate_message {
    __u64 instance_rate_bps; 
    __u64 rate_bps;
    __u64 peak_rate_bps;
    __u64 smooth_rate_bps;
    __u64    timestamp;
};

struct flow_rate_info {
    __u64 window_start_ns;
    __u64 last_ns;   
    __u64 total_bytes;
    __u64 packet_bytes;     
    struct flow_rate_message msg;   
};

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
    __u64 now = flow_info->msg.timestamp;
    flow_info->total_bytes += packet_size;
    flow_info->msg.rate_bps = (flow_info->total_bytes * NSEC_PER_SEC) / (now - flow_info->window_start_ns);
    if (now - flow_info->last_ns >= NSEC_PER_SEC) {
        flow_info->msg.instance_rate_bps = (flow_info->packet_bytes * NSEC_PER_SEC) / (now - flow_info->last_ns);
        if (flow_info->msg.instance_rate_bps > flow_info->msg.peak_rate_bps) {
            flow_info->msg.peak_rate_bps = flow_info->msg.instance_rate_bps;
        }

        if (flow_info->msg.smooth_rate_bps != 0) {
            flow_info->msg.smooth_rate_bps = (flow_info->msg.smooth_rate_bps - (flow_info->msg.smooth_rate_bps >> 3)) + (flow_info->msg.instance_rate_bps  >> 3);
        } else {
            flow_info->msg.smooth_rate_bps = flow_info->msg.instance_rate_bps;
        }
        flow_info->last_ns = now;
        flow_info->packet_bytes = packet_size;
    } else {
        flow_info->packet_bytes += packet_size;
    }
}

static __inline void update_flow(void *flow_rate_stats, struct flow_rate_message *mes, uint32_t packet_size) 
{
    mes->timestamp = start_to_now_ns();
    __u64 now = mes->timestamp;

    __u32 flow_key = 1;
    struct flow_rate_info *info = bpf_map_lookup_elem(flow_rate_stats, &flow_key);
    if (!info) {
        struct flow_rate_info new_flow = {
            .window_start_ns = now,
            .total_bytes = packet_size,
            .packet_bytes = packet_size,
            .last_ns = now,
            .msg = {0}
        };
        bpf_map_update_elem(flow_rate_stats, &flow_key, &new_flow, BPF_ANY); 
    }
    info = bpf_map_lookup_elem(flow_rate_stats, &flow_key);
    if (info) {
        info->msg.timestamp = now;
        update_flow_rate(info, packet_size);
        mes->rate_bps = info->msg.rate_bps;
        mes->instance_rate_bps = info->msg.instance_rate_bps;
        mes->peak_rate_bps = info->msg.peak_rate_bps;
        mes->smooth_rate_bps = info->msg.smooth_rate_bps;
    }
}



#endif
