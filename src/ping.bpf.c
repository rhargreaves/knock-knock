#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include "packet.h"

#define MAX_SEQUENCE_LENGTH 10

struct port_sequence {
    u16 ports[MAX_SEQUENCE_LENGTH];
    u8 length;
    u64 timeout_ms;
};

struct ip_state {
    u8 sequence_step;
    u64 last_packet_time;
    u8 sequence_complete;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10000);
    __type(key, __u32); // source IP
    __type(value, struct ip_state);
} ip_tracking_map SEC(".maps");

SEC("xdp")
int ping(struct xdp_md* ctx)
{
    struct port_sequence seq = {
        .ports = {1234},
        .length = 1,
        .timeout_ms = 1000,
    };

    long protocol = lookup_protocol(ctx);
    if (protocol == IPPROTO_ICMP) {
        bpf_printk("Hello ping");
        return XDP_PASS;
    }

    if (protocol == IPPROTO_UDP) {
        u16 port = lookup_port(ctx);
        bpf_printk("Hello udp port %d", port);
        if (port == 7777) {
            bpf_printk("Hello udp port 7777");
            return XDP_PASS;
        }
    }

    if (protocol == IPPROTO_TCP) {
        u16 port = lookup_port(ctx);
        if (port == 6666) {
            bpf_printk("Hello tcp port 6666");
            return XDP_DROP;
        }
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
