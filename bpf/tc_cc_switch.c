#include "common.h"
#include "hdr_parse.h"
#include "rate_limit.h"

char LICENSE[] SEC("license") = "GPL";

struct message_get {
    __u64 ret;
	__u64 timestamp;
};


struct cc_rule {
    struct ip_addr ip;
    __u16 port;
    char algo[16];
    __u8 remote : 1;
};


struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 16);
} ringbuf SEC(".maps");


struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key,  __u32);              
    __type(value, struct cc_rule);
    __uint(max_entries, 1024);
} cc_rule_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, struct cc_rule);
} cc_map SEC(".maps");


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

SEC("sockops")
int cc_switch_sockops(struct bpf_sock_ops *skops)
{
    struct message_get mes = {0};
    int key = 0;
    int op = skops->op;

    if (!skops->is_fullsock) {
        return 0;
    }

    struct cc_rule *rule = bpf_map_lookup_elem(&cc_map, &key);
    if (!rule)
        return 0;

    __u16 sport = skops->local_port;
    __u16 dport = skops->remote_port;

    if (rule->remote) {
        if (dport != rule->port) {
            return 0;
        }
        
        if (skops->family == AF_INET) {
            //fuck! Why it is little endian??? Maybe it is a history problem.
            if (bpf_htonl(skops->remote_ip4) != rule->ip.v4) {
                return 0;
            } 

        } else if (skops->family == AF_INET6) {
            //fuck! You can't use for{} or inline.
            if (bpf_htonl(skops->remote_ip6[0]) != rule->ip.v6[0]) return 0;
            if (bpf_htonl(skops->remote_ip6[1]) != rule->ip.v6[1]) return 0;
            if (bpf_htonl(skops->remote_ip6[2]) != rule->ip.v6[2]) return 0;
            if (bpf_htonl(skops->remote_ip6[3]) != rule->ip.v6[3]) return 0;
        }
    } else {
        if (sport != rule->port) {
            return 0;
        }

        if (skops->family == AF_INET) {
            if (bpf_htonl(skops->local_ip4) != rule->ip.v4) {
                return 0;
            }
        } else if (skops->family == AF_INET6) {
            if (bpf_htonl(skops->local_ip6[0]) != rule->ip.v6[0]) return 0;
            if (bpf_htonl(skops->local_ip6[1]) != rule->ip.v6[1]) return 0;
            if (bpf_htonl(skops->local_ip6[2]) != rule->ip.v6[2]) return 0;
            if (bpf_htonl(skops->local_ip6[3]) != rule->ip.v6[3]) return 0;
        }
    }
    
    char *algo = rule->algo;
    if (!algo)  return 0;

    int ret = bpf_setsockopt(skops, IPPROTO_TCP, TCP_CONGESTION,
                             algo, sizeof(rule->algo));
    mes.ret = ret;

    send_message(&mes);

    return 0;
}
