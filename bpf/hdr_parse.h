#ifndef HDR_PARSE_H
#define HDR_PARSE_H
#include "common.h"

struct ip_addr {
    __u8 version;  

    union {
        __u32 v4;    
        __u32 v6[4];   
    };
};

struct packet_tuple {
    struct ip_addr src;
    struct ip_addr dst;

    __u16 src_port;
    __u16 dst_port;
    __u8  protocol;
};

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



static struct udphdr *udp_hdr(struct sk_buff *skb, u32 offset)
{
    struct bpf_dynptr ptr;
    struct udphdr udph = {};

    if (skb->len <= offset) {
        return NULL;
    }

    if (bpf_dynptr_from_skb((struct __sk_buff *)skb, 0, &ptr)) {
        return NULL;
    }

    return bpf_dynptr_slice(&ptr, offset, &udph, sizeof(udph));
}

static struct tcphdr *tcp_hdr(struct sk_buff *skb, u32 offset)
{
    struct bpf_dynptr ptr;
    struct tcphdr tcph = {};

    if (skb->len <= offset) {
        return NULL;
    }

    if (bpf_dynptr_from_skb((struct __sk_buff *)skb, 0, &ptr)) {
        return NULL;
    }

    return bpf_dynptr_slice(&ptr, offset, &tcph, sizeof(tcph));
}

static struct iphdr *ip_hdr(struct sk_buff *skb)
{
    struct bpf_dynptr ptr;
    struct iphdr iph = {};

    if (skb->len <= 20) {
        return NULL;
    }

    if (bpf_dynptr_from_skb((struct __sk_buff *)skb, 0, &ptr)) {
        return NULL;
    }

    return bpf_dynptr_slice(&ptr, 0, &iph, sizeof(iph));
}

static struct ipv6hdr *ipv6_hdr(struct sk_buff *skb)
{
    struct bpf_dynptr ptr;
    struct ipv6hdr ip6h = {};

    if (skb->len <= 40) {
        return NULL;
    }

    if (bpf_dynptr_from_skb((struct __sk_buff *)skb, 0, &ptr)) {
        return NULL;
    }

    return bpf_dynptr_slice(&ptr, 0, &ip6h, sizeof(ip6h));
}

static __inline bool parse_net(struct sk_buff *skb, struct packet_tuple *t)
{
    if (!skb || !t)
        return false;

    if (skb->len < sizeof(struct ethhdr))
        return false;

    if (skb->protocol == bpf_htons(ETH_P_IP)) {
        struct iphdr *iph = ip_hdr((struct sk_buff *)skb);
        if (!iph)
            return false;

        if (iph->version != 4)
            return false;

         __u32 iphl = iph->ihl * 4;
        if (iph->ihl < 5 || skb->len <= iphl) {
            return false;
        }

        t->src.version = 4;
        t->dst.version = 4;
        t->protocol = iph->protocol;

        t->src.v4 = bpf_ntohl(iph->saddr);
        t->dst.v4 = bpf_ntohl(iph->daddr);

        if (iph->protocol == IPPROTO_UDP) {
            if (skb->len < iphl + sizeof(struct udphdr))
                return false;

            struct udphdr *udph = udp_hdr((struct sk_buff *)skb, iphl);
            if (!udph)
                return false;

            t->src_port = bpf_ntohs(udph->source);
            t->dst_port = bpf_ntohs(udph->dest);
            return true;
        }

        if (iph->protocol == IPPROTO_TCP) {
            if (skb->len < iphl + sizeof(struct tcphdr))
                return false;

            struct tcphdr *tcph = tcp_hdr((struct sk_buff *)skb, iphl);
            if (!tcph)
                return false;

            t->src_port = bpf_ntohs(tcph->source);
            t->dst_port = bpf_ntohs(tcph->dest);
            return true;
        }

        t->src_port = 0;
        t->dst_port = 0;
        return true;
    }

    if (skb->protocol == bpf_htons(ETH_P_IPV6)) {
        struct ipv6hdr *ip6h = ipv6_hdr((struct sk_buff *)skb);
        if (!ip6h)
            return false;

        if (ip6h->version != 6)
            return false;

        __u32 ip6hl = sizeof(struct ipv6hdr); 

        t->src.version = 6;
        t->dst.version = 6;
        t->protocol = ip6h->nexthdr;

        __builtin_memcpy(t->src.v6, ip6h->saddr.in6_u.u6_addr8, 16);
        __builtin_memcpy(t->dst.v6, ip6h->daddr.in6_u.u6_addr8, 16);

        if (t->protocol == IPPROTO_UDP) {
            if (skb->len < ip6hl + sizeof(struct udphdr))
                return false;

            struct udphdr *udph = udp_hdr((struct sk_buff *)skb, ip6hl);
            if (!udph)
                return false;

            t->src_port = bpf_ntohs(udph->source);
            t->dst_port = bpf_ntohs(udph->dest);
            return true;
        }

        if (t->protocol == IPPROTO_TCP) {
            if (skb->len < ip6hl + sizeof(struct tcphdr))
                return false;

            struct tcphdr *tcph = tcp_hdr((struct sk_buff *)skb, ip6hl);
            if (!tcph)
                return false;

            t->src_port = bpf_ntohs(tcph->source);
            t->dst_port = bpf_ntohs(tcph->dest);
            return true;
        }

        t->src_port = 0;
        t->dst_port = 0;
        return true;
    }

    return false;
}


#endif