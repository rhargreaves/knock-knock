#include <bpf/libbpf.h>
#include <net/if.h>
#include <sys/resource.h>
#include <unistd.h>
#include <signal.h>
#include <cstring>
#include <cerrno>
#include <cstdio>
#include "knock.skel.h"
#include "knock.h"

static volatile sig_atomic_t keep_running = 1;

void signal_handler(int sig) noexcept
{
    keep_running = 0;
}

int main(int argc, char** argv)
{
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    if (argc < 2) {
        printf("Usage: %s <interface>\n", argv[0]);
        return 1;
    }

    const char* ifname = argv[1];
    int ifindex = if_nametoindex(ifname);
    if (!ifindex) {
        printf("Failed to get interface index for %s\n", ifname);
        return 1;
    }

    __u16 target_port;
    if (argc > 2) {
        target_port = atoi(argv[2]);
    } else {
        printf("Target port is not specified\n");
        return 1;
    }

    struct port_sequence seq;
    if (argc > 3) {
        seq.length = 0;
        for (int i = 3; i < argc && seq.length < MAX_SEQUENCE_LENGTH; i++) {
            seq.ports[seq.length] = atoi(argv[i]);
            seq.length++;
        }
    }

    printf("Target port: %d\n", target_port);
    printf("Knock sequence: ");
    for (int i = 0; i < seq.length; i++) {
        printf("%d ", seq.ports[i]);
    }
    printf("\n");

    struct rlimit r = { RLIM_INFINITY, RLIM_INFINITY };
    if (setrlimit(RLIMIT_MEMLOCK, &r) != 0) {
        printf("Failed to set memory lock limit: %s\n", strerror(errno));
        return 1;
    }

    knock_bpf* skel = knock_bpf__open();
    if (!skel) {
        printf("Failed to open BPF skeleton\n");
        return 1;
    }

    if (knock_bpf__load(skel) != 0) {
        printf("Failed to load BPF program\n");
        knock_bpf__destroy(skel);
        return 1;
    }

    __u32 key = 0;

    if (bpf_map__update_elem(
            skel->maps.target_port_map, &key, sizeof(key), &target_port, sizeof(target_port), 0)
        != 0) {
        printf("Failed to update target port configuration\n");
        knock_bpf__destroy(skel);
        return 1;
    }

    if (bpf_map__update_elem(skel->maps.config_map, &key, sizeof(key), &seq, sizeof(seq), 0) != 0) {
        printf("Failed to update sequence configuration\n");
        knock_bpf__destroy(skel);
        return 1;
    }

    bpf_link* link = bpf_program__attach_xdp(skel->progs.knock, ifindex);
    if (!link) {
        printf("Failed to attach XDP program\n");
        knock_bpf__destroy(skel);
        return 1;
    }

    printf("Attached XDP program to %s\n", ifname);
    printf("Waiting for packets (Ctrl+C to exit)...\n");

    while (keep_running) {
        sleep(1);
    }

    bpf_link__destroy(link);
    knock_bpf__destroy(skel);
    printf("Detached XDP program from %s\n", ifname);

    return 0;
}