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
