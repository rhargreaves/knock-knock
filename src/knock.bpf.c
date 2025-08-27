#include "knock.bpf.h"
#include "packet.h"

static __always_inline const struct knock_config* get_and_validate_config(struct xdp_md* ctx)
{
    const __u32 key = 0;
    const struct knock_config* config = bpf_map_lookup_elem(&config_map, &key);
    if (!config) {
        bpf_printk("Config map not found");
        return NULL;
    }

    if (config->seq.length > MAX_SEQUENCE_LENGTH) {
        bpf_printk("Sequence length is too long");
        return NULL;
    }

    return config;
}

static __always_inline int handle_udp_knock(
    u32 source_ip, u16 port, const struct port_sequence* seq)
{
    struct ip_state* state = bpf_map_lookup_elem(&ip_tracking_map, &source_ip);

    if (!state) {
        if (port == seq->ports[0]) {
            bpf_printk("Code 1 passed.");
            struct ip_state new_state = {
                .sequence_step = 0,
                .last_packet_time = bpf_ktime_get_ns(),
                .sequence_complete = false,
            };
            bpf_map_update_elem(&ip_tracking_map, &source_ip, &new_state, BPF_ANY);
        }
    } else {
        if (state->sequence_step < seq->length && state->sequence_step + 1 < MAX_SEQUENCE_LENGTH
            && port == seq->ports[state->sequence_step + 1]) {

            state->sequence_step++;
            state->last_packet_time = bpf_ktime_get_ns();
            state->sequence_complete = (state->sequence_step == seq->length - 1);

            bpf_printk("Code %d passed.", state->sequence_step + 1);
            if (state->sequence_complete) {
                bpf_printk("Sequence complete.");
            }
            bpf_map_update_elem(&ip_tracking_map, &source_ip, state, BPF_ANY);
        } else {
            bpf_printk("Sequence reset.");
            bpf_map_delete_elem(&ip_tracking_map, &source_ip);
        }
    }

    return XDP_PASS;
}

static __always_inline int handle_tcp_connection(u32 source_ip, u16 port, u16 target_port)
{
    if (port != target_port) {
        return XDP_PASS;
    }

    bpf_printk("Hello tcp port %d", port);

    struct ip_state* state = bpf_map_lookup_elem(&ip_tracking_map, &source_ip);
    if (!state) {
        bpf_printk("Dropping packet because state is not found");
        return XDP_DROP;
    }

    if (state->sequence_complete) {
        bpf_printk("Allowing packet because sequence is complete");
        return XDP_PASS;
    }

    bpf_printk("Dropping packet because sequence is not complete");
    return XDP_DROP;
}

SEC("xdp")
int knock(struct xdp_md* ctx)
{
    const struct knock_config* config = get_and_validate_config(ctx);
    if (!config) {
        return XDP_PASS;
    }

    long protocol = lookup_protocol(ctx);
    u32 source_ip = lookup_source_ip(ctx);
    u16 port = lookup_port(ctx);

    bpf_printk("Hello source ip %d", source_ip);

    switch (protocol) {
    case IPPROTO_UDP:
        bpf_printk("Hello udp port %d", port);
        return handle_udp_knock(source_ip, port, &config->seq);

    case IPPROTO_TCP:
        return handle_tcp_connection(source_ip, port, config->target_port);
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
