#include "common.h"

char __license[] SEC("license") = "GPL";

#define CG_ACT_OK 1
#define CG_ACT_SHOT 0

struct message_get {  
    __u64 instance_rate_bps; 
    __u64 rate_bps;
    __u64 peak_rate_bps;
    __u64 smoothed_rate_bps;
	__u64 timestamp;
};

struct cgroup_rule {
    __u64    rate_bps;    
    __u8     gress;     
    __u32    time_scale; 
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
    __type(value, struct cgroup_rule);
    __uint(max_entries, 1024);
} cgroup_rules SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key,  __u64);
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
	e->timestamp = start_to_now_ns();

	bpf_ringbuf_submit(e, 0);
}

static __inline __u32 get_current_pid(void) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (task) {
        __u32 pid = 0;
        bpf_probe_read_kernel(&pid, sizeof(pid), &task->pid);
        return pid;
    }
    return 0;
}

static __inline __u64 get_cgroup_id(void) {
    return bpf_get_current_cgroup_id();
}

static int cgroup_handle(struct __sk_buff *ctx, int gress)
{
    struct cgroup_rule *rule;
    struct message_get mes = {0};
    __u32 rule_key = 0;
    __u32 pid = get_current_pid();
    __u64 cgroup_id = get_cgroup_id();

    rule = bpf_map_lookup_elem(&cgroup_rules, &rule_key);
    if (!rule || (rule->gress != gress)) {
        return CG_ACT_OK;
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

    __u64 bucket_key = cgroup_id;
    struct rate_limit rate = {
        .bucket_key = &bucket_key,
        .buckets = &buckets,
        .packet_len = ctx->len,
        .rate_bps = rule->rate_bps,
        .time_scale = rule->time_scale
    };
    if (rate_limit_check(&rate) == ACCEPT) {
        return CG_ACT_OK;
    }
    return CG_ACT_SHOT;
}

SEC("cgroup_skb/egress")
int cgroup_skb_egress(struct __sk_buff *ctx) 
{
    return cgroup_handle(ctx, EGRESS);
}

SEC("cgroup_skb/ingress")
int cgroup_skb_ingress(struct __sk_buff *ctx)
{
    return cgroup_handle(ctx, INGRESS);
}