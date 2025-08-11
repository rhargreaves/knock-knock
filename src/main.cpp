#include <bpf/libbpf.h>
#include <net/if.h>
#include <sys/resource.h>
#include <unistd.h>
#include "ping.skel.h"

int main(int argc, char** argv)
{
    const char* ifname = argc > 1 ? argv[1] : "eth0";
    int ifindex = if_nametoindex(ifname);
    if (!ifindex) {
        printf("Failed to get interface index for %s\n", ifname);
        return 1;
    }

    struct rlimit r = { RLIM_INFINITY, RLIM_INFINITY };
    if (setrlimit(RLIMIT_MEMLOCK, &r) != 0) {
        printf("Failed to set memory lock limit\n");
        return 1;
    }

    ping_bpf* skel = ping_bpf__open();
    if (!skel) {
        printf("Failed to open BPF skeleton\n");
        return 1;
    }
    if (ping_bpf__load(skel) != 0) {
        printf("Failed to load BPF program\n");
        ping_bpf__destroy(skel);
        return 1;
    }

    bpf_link* link = bpf_program__attach_xdp(skel->progs.ping, ifindex);
    if (!link) {
        printf("Failed to attach XDP program\n");
        ping_bpf__destroy(skel);
        return 1;
    }

    printf("Attached XDP program to %s\n", ifname);
    pause();

    bpf_link__destroy(link);
    ping_bpf__destroy(skel);
    printf("Detached XDP program from %s\n", ifname);

    return 0;
}