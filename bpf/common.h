#ifndef COMMON_H
#define COMMON_H
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

#define NSEC_PER_SEC 1000000000ull

#define ETH_P_IP 0x0800
#define ETH_P_IPV6  0x86DD
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17

#define AF_INET   2
#define AF_INET6  10

#define TCP_CONGESTION  13

#define ACCEPT 1
#define DROP   0

#define EGRESS   1
#define INGRESS  0

static __inline __u64 start_to_now_ns(void) 
{
    return bpf_ktime_get_ns();
}


#endif
