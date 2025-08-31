#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

char __license[] SEC("license") = "GPL";

#define EGRESS   1
#define INGRESS  0

struct cgroup_rule {
    __u64    rate_bps;    
    __u8     gress;     
    __u32    time_scale; 
};

struct rate_bucket {
    __u64    ts_ns;        
    __u64    tokens;      
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} ringbuf SEC(".maps");

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

#define NSEC_PER_SEC 1000000000ull
#define CG_ACT_OK 1
#define CG_ACT_SHOT 0

#define ACCEPT CG_ACT_OK
#define DROP   CG_ACT_SHOT

static __inline __u64 now_ns(void) {
    return bpf_ktime_get_ns();
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


static int cgroup_handle(struct __sk_buff *ctx, int gress)
{
    __u64 now = now_ns();
    __u64 delta_ns;
    struct rate_bucket *b;
    struct cgroup_rule *rule;
    __u32 rule_key = 0;
    __u32 pid = get_current_pid();
    __u64 cgroup_id = get_cgroup_id();

    rule = bpf_map_lookup_elem(&cgroup_rules, &rule_key);
    if (!rule || (rule->gress != gress)) {
        return CG_ACT_OK;
    }

    __u64 bucket_key = cgroup_id;
    rate_limit_check(bucket_key, rule->rate_bps, rule->time_scale, ctx->len);

    return CG_ACT_OK;
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