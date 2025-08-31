#include "knock.bpf.h"
#include "packet.h"

static __always_inline const struct knock_config* get_and_validate_config(struct xdp_md* ctx)
{
    const __u32 key = 0;
    const struct knock_config* config = bpf_map_lookup_elem(&config_map, &key);
    if (!config) {
        log_error("config map not found");
        return NULL;
    }

    if (config->seq.length > MAX_SEQUENCE_LENGTH) {
        log_error("config sequence length is too long");
        return NULL;
    }

    return config;
}

static __always_inline int handle_udp_knock(
    u32 source_ip, u16 port, const struct port_sequence* seq)
{
    log_debug("source ip: %d", source_ip);
    log_debug("udp port: %d", port);

    struct ip_state new_state = {
        .sequence_step = 0, .last_packet_time = bpf_ktime_get_ns(), .sequence_complete = false
    };
    struct ip_state* existing_state = bpf_map_lookup_elem(&ip_tracking_map, &source_ip);
    struct ip_state* state = existing_state != NULL ? existing_state : &new_state;

    if (state->sequence_step >= seq->length) {
        log_error("sequence step > length");
        return XDP_PASS;
    }

    if (state->sequence_step >= MAX_SEQUENCE_LENGTH) {
        log_error("sequence step out of bounds");
        return XDP_PASS;
    }

    if (port == seq->ports[state->sequence_step]) {

        const __u64 current_time = bpf_ktime_get_ns();
        if (current_time - state->last_packet_time > MS_TO_NS(seq->timeout_ms)) {
            log_info("sequence timeout");
            bpf_map_delete_elem(&ip_tracking_map, &source_ip);
            return XDP_PASS;
        }

        state->sequence_step++;
        state->last_packet_time = current_time;
        state->sequence_complete = (state->sequence_step == seq->length);

        log_info("code %d passed", state->sequence_step);
        if (state->sequence_complete) {
            log_info("sequence complete");
        }
        bpf_map_update_elem(&ip_tracking_map, &source_ip, state, BPF_ANY);
    } else if (existing_state) {
        log_info("sequence reset");
        bpf_map_delete_elem(&ip_tracking_map, &source_ip);
    }

    return XDP_PASS;
}

static __always_inline int handle_tcp(u32 source_ip, u16 port, u16 target_port, u64 session_timeout)
{
    if (port != target_port) {
        return XDP_PASS;
    }

    log_debug("source ip: %d", source_ip);
    log_debug("tcp port: %d", port);

    struct ip_state* state = bpf_map_lookup_elem(&ip_tracking_map, &source_ip);
    if (!state) {
        log_info("dropping packet because state is not found");
        return XDP_DROP;
    }

    if (state->sequence_complete) {
        const __u64 current_time = bpf_ktime_get_ns();
        if (current_time - state->last_packet_time > MS_TO_NS(session_timeout)) {
            log_info("session timed out");
            bpf_map_delete_elem(&ip_tracking_map, &source_ip);
            return XDP_DROP;
        }
        return XDP_PASS;
    }

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

    switch (protocol) {
    case IPPROTO_UDP:
        return handle_udp_knock(source_ip, port, &config->seq);
    case IPPROTO_TCP:
        return handle_tcp(source_ip, port, config->target_port, config->session_timeout);
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
