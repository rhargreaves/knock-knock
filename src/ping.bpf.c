#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include "packet.h"

SEC("xdp")
int ping(struct xdp_md* ctx)
{
    long protocol = lookup_protocol(ctx);
    if (protocol == IPPROTO_ICMP) {
        bpf_printk("Hello ping");
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
