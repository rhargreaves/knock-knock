#include "knock.bpf.h"
#include "packet.h"

SEC("xdp")
int knock(struct xdp_md* ctx)
{
    const u16 target_port = 6666;

    const struct port_sequence seq = {
        .ports = { 1111, 2222, 3333 },
        .length = 3,
        .timeout_ms = 1000,
    };

    long protocol = lookup_protocol(ctx);
    if (protocol == IPPROTO_UDP) {
        u16 port = lookup_port(ctx);
        u32 source_ip = lookup_source_ip(ctx);
        bpf_printk("Hello source ip %d", source_ip);
        bpf_printk("Hello udp port %d", port);

        struct ip_state* state = bpf_map_lookup_elem(&ip_tracking_map, &source_ip);
        if (!state) {
            bpf_printk("State is not found");
            if (port == seq.ports[0]) {
                bpf_printk("Code 1 passed.");
                struct ip_state new_state = {
                    .sequence_step = 0,
                    .last_packet_time = bpf_ktime_get_ns(),
                    .sequence_complete = false,
                };
                bpf_map_update_elem(&ip_tracking_map, &source_ip, &new_state, BPF_ANY);
                state = &new_state;
            }
        } else {
            if (state->sequence_step == 0 && port == seq.ports[1]) {
                bpf_printk("Code 2 passed.");
                state->sequence_step = 1;
                state->last_packet_time = bpf_ktime_get_ns();
                state->sequence_complete = false;
                bpf_map_update_elem(&ip_tracking_map, &source_ip, state, BPF_ANY);
            } else if (state->sequence_step == 1 && port == seq.ports[2]) {
                bpf_printk("Code 3 passed. Sequence complete.");
                state->sequence_step = 2;
                state->last_packet_time = bpf_ktime_get_ns();
                state->sequence_complete = true;
                bpf_map_update_elem(&ip_tracking_map, &source_ip, state, BPF_ANY);
            } else {
                bpf_printk("Code reset.");
                bpf_map_delete_elem(&ip_tracking_map, &source_ip);
            }
        }

        return XDP_PASS;
    }

    if (protocol == IPPROTO_TCP) {
        u16 port = lookup_port(ctx);
        if (port == target_port) {
            bpf_printk("Hello tcp port %d", port);

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
            return XDP_DROP;
        }
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
