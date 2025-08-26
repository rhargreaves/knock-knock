#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include "packet.h"

#define MAX_SEQUENCE_LENGTH 10

#define ICMP_ECHO 8

struct port_sequence {
    u16 ports[MAX_SEQUENCE_LENGTH];
    u8 length;
    u64 timeout_ms;
};

struct ip_state {
    u8 sequence_step;
    u64 last_packet_time;
    bool sequence_complete;
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
        .ports = { 1111 },
        .length = 1,
        .timeout_ms = 1000,
    };

    long protocol = lookup_protocol(ctx);
    if (protocol == IPPROTO_UDP) {
        u16 port = lookup_port(ctx);
        if (port == 1111) {
            u32 source_ip = lookup_source_ip(ctx);
            bpf_printk("Hello source ip %d", source_ip);
            bpf_printk("Hello udp port %d", port);

            struct ip_state* state = bpf_map_lookup_elem(&ip_tracking_map, &source_ip);
            if (!state) {
                struct ip_state new_state = {
                    .sequence_step = 1,
                    .last_packet_time = bpf_ktime_get_ns(),
                    .sequence_complete = true,
                };
                bpf_map_update_elem(&ip_tracking_map, &source_ip, &new_state, BPF_ANY);
                state = &new_state;
            }

            return XDP_PASS;
        }
    }

    if (protocol == IPPROTO_TCP) {
        u16 port = lookup_port(ctx);
        if (port == 6666) {
            bpf_printk("Hello tcp port 6666");

            u32 source_ip = lookup_source_ip(ctx);
            struct ip_state* state = bpf_map_lookup_elem(&ip_tracking_map, &source_ip);
            if (!state) {
                bpf_printk("Dropping packet because state is not found");
                return XDP_DROP;
            }

            if (state->sequence_complete) {
                bpf_printk("Allowing packet because sequence is complete");
                return XDP_PASS;
            }
        }
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
