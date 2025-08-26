#pragma once
#include "vmlinux.h"

#define TC_ACT_UNSPEC (-1)
#define TC_ACT_OK 0
#define TC_ACT_RECLASSIFY 1
#define TC_ACT_SHOT 2

#define ETH_P_IP 0x0800
#define ICMP_PING 8

#define ETH_ALEN 6
#define ETH_HLEN 14

#define IP_SRC_OFF (ETH_HLEN + offsetof(struct iphdr, saddr))
#define IP_DST_OFF (ETH_HLEN + offsetof(struct iphdr, daddr))

#define ICMP_CSUM_OFF (ETH_HLEN + sizeof(struct iphdr) + offsetof(struct icmphdr, checksum))
#define ICMP_TYPE_OFF (ETH_HLEN + sizeof(struct iphdr) + offsetof(struct icmphdr, type))
#define ICMP_CSUM_SIZE sizeof(__u16)

// Returns the protocol byte for an IP packet, 0 for anything else
// static __always_inline unsigned char lookup_protocol(struct xdp_md *ctx)
unsigned char lookup_protocol(struct xdp_md* ctx)
{
    unsigned char protocol = 0;

    void* data = (void*)(long)ctx->data;
    void* data_end = (void*)(long)ctx->data_end;
    struct ethhdr* eth = data;
    if (data + sizeof(struct ethhdr) > data_end)
        return 0;

    // Check that it's an IP packet
    if (bpf_ntohs(eth->h_proto) == ETH_P_IP) {
        // Return the protocol of this packet
        // 1 = ICMP
        // 6 = TCP
        // 17 = UDP
        struct iphdr* iph = data + sizeof(struct ethhdr);
        if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) <= data_end)
            protocol = iph->protocol;
    }
    return protocol;
}

unsigned int lookup_port(struct xdp_md* ctx)
{
    unsigned int port = 0;

    void* data = (void*)(long)ctx->data;
    void* data_end = (void*)(long)ctx->data_end;
    struct ethhdr* eth = data;
    if (data + sizeof(struct ethhdr) > data_end)
        return 0;

    if (bpf_ntohs(eth->h_proto) == ETH_P_IP) {
        struct iphdr* iph = data + sizeof(struct ethhdr);
        if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end)
            return 0;

        switch (iph->protocol) {
            case IPPROTO_TCP: {
                struct tcphdr* tcph = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
                if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr)
                    <= data_end)
                    port = bpf_ntohs(tcph->dest);
                break;
            }
            case IPPROTO_UDP: {
                struct udphdr* udph = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
                if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr)
                    <= data_end)
                    port = bpf_ntohs(udph->dest);
                break;
            }
            default:
                break;
        }
    }
    return port;
}

unsigned int lookup_source_ip(struct xdp_md* ctx)
{
    unsigned int source_ip = 0;

    void* data = (void*)(long)ctx->data;
    void* data_end = (void*)(long)ctx->data_end;
    struct ethhdr* eth = data;
    if (data + sizeof(struct ethhdr) > data_end)
        return 0;

    if (bpf_ntohs(eth->h_proto) == ETH_P_IP) {
        struct iphdr* iph = data + sizeof(struct ethhdr);
        if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end)
            return 0;

        source_ip = bpf_ntohl(iph->saddr);
    }

    return source_ip;
}

unsigned int lookup_icmp_type(struct xdp_md* ctx)
{
    unsigned int icmp_type = 0;

    void* data = (void*)(long)ctx->data;
    void* data_end = (void*)(long)ctx->data_end;
    struct ethhdr* eth = data;
    if (data + sizeof(struct ethhdr) > data_end)
        return 0;

    if (bpf_ntohs(eth->h_proto) == ETH_P_IP) {
        struct iphdr* iph = data + sizeof(struct ethhdr);
        if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end)
            return 0;

        if (iph->protocol == IPPROTO_ICMP) {
            struct icmphdr* icmph = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
            if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct icmphdr)
                <= data_end)
                icmp_type = icmph->type;
        }
    }

    return icmp_type;
}