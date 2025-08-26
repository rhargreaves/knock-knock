#pragma once
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define TC_ACT_UNSPEC (-1)
#define TC_ACT_OK 0
#define TC_ACT_RECLASSIFY 1
#define TC_ACT_SHOT 2

#define ETH_P_IP 0x0800

#define ETH_ALEN 6
#define ETH_HLEN 14

#define IP_SRC_OFF (ETH_HLEN + offsetof(struct iphdr, saddr))
#define IP_DST_OFF (ETH_HLEN + offsetof(struct iphdr, daddr))

#define ICMP_CSUM_OFF (ETH_HLEN + sizeof(struct iphdr) + offsetof(struct icmphdr, checksum))
#define ICMP_TYPE_OFF (ETH_HLEN + sizeof(struct iphdr) + offsetof(struct icmphdr, type))
#define ICMP_CSUM_SIZE sizeof(__u16)

static __always_inline struct iphdr* get_ip_header(struct xdp_md* ctx)
{
    void* data = (void*)(long)ctx->data;
    void* data_end = (void*)(long)ctx->data_end;
    struct ethhdr* eth = (struct ethhdr*)data;

    if ((char*)data + sizeof(struct ethhdr) > (char*)data_end)
        return (struct iphdr*)0;

    if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
        return (struct iphdr*)0;

    struct iphdr* iph = (struct iphdr*)((char*)data + sizeof(struct ethhdr));
    if ((char*)data + sizeof(struct ethhdr) + sizeof(struct iphdr) > (char*)data_end)
        return (struct iphdr*)0;

    return iph;
}

static __always_inline unsigned char lookup_protocol(struct xdp_md* ctx)
{
    struct iphdr* iph = get_ip_header(ctx);
    return iph ? iph->protocol : 0;
}

static __always_inline unsigned int lookup_port(struct xdp_md* ctx)
{
    struct iphdr* iph = get_ip_header(ctx);
    if (!iph)
        return 0;

    void* data_end = (void*)(long)ctx->data_end;
    void* transport_header = (char*)iph + sizeof(struct iphdr);

    switch (iph->protocol) {
    case IPPROTO_TCP: {
        struct tcphdr* tcph = (struct tcphdr*)transport_header;
        if ((char*)transport_header + sizeof(struct tcphdr) <= (char*)data_end)
            return bpf_ntohs(tcph->dest);
        break;
    }
    case IPPROTO_UDP: {
        struct udphdr* udph = (struct udphdr*)transport_header;
        if ((char*)transport_header + sizeof(struct udphdr) <= (char*)data_end)
            return bpf_ntohs(udph->dest);
        break;
    }
    }
    return 0;
}

static __always_inline unsigned int lookup_source_ip(struct xdp_md* ctx)
{
    struct iphdr* iph = get_ip_header(ctx);
    return iph ? bpf_ntohl(iph->saddr) : 0;
}
