#include <bpf/libbpf.h>
#include <net/if.h>
#include <sys/resource.h>
#include <unistd.h>
#include <signal.h>
#include <iostream>
#include "knock.skel.h"
#include "knock.h"

static volatile sig_atomic_t keep_running = 1;

void signal_handler(int sig) noexcept
{
    keep_running = 0;
}

static void print_config(const struct knock_config& config)
{
    std::cout << "Target port: " << config.target_port << '\n';
    std::cout << "Knock sequence: ";
    for (int i = 0; i < config.seq.length; i++) {
        std::cout << config.seq.ports[i] << ' ';
    }
    std::cout << '\n';
}

int main(int argc, char** argv)
{
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <interface> <target_port> [<sequence_length>]\n";
        return 1;
    }

    const char* ifname = argv[1];
    int ifindex = if_nametoindex(ifname);
    if (!ifindex) {
        std::cerr << "Failed to get interface index for " << ifname << '\n';
        return 1;
    }

    __u16 target_port;
    if (argc > 2) {
        target_port = atoi(argv[2]);
    } else {
        std::cerr << "Target port is not specified\n";
        return 1;
    }

    if (argc < 4) {
        std::cerr << "Sequence not specified\n";
        return 1;
    }

    if (argc > MAX_SEQUENCE_LENGTH + 3) {
        std::cerr << "Error: sequence length is too long\n";
        return 1;
    }

    struct knock_config config = { 0 };
    config.target_port = target_port;
    if (argc > 3) {
        config.seq.length = 0;
        for (int i = 3; i < argc && config.seq.length < MAX_SEQUENCE_LENGTH; i++) {
            config.seq.ports[config.seq.length] = atoi(argv[i]);
            config.seq.length++;
        }
    }
    print_config(config);

    struct rlimit r = { RLIM_INFINITY, RLIM_INFINITY };
    if (setrlimit(RLIMIT_MEMLOCK, &r) != 0) {
        std::cerr << "Failed to set memory lock limit: " << std::system_category().message(errno)
                  << '\n';
        return 1;
    }

    knock_bpf* skel = knock_bpf__open();
    if (!skel) {
        std::cerr << "Failed to open BPF skeleton\n";
        return 1;
    }

    if (knock_bpf__load(skel) != 0) {
        std::cerr << "Failed to load BPF program\n";
        knock_bpf__destroy(skel);
        return 1;
    }

    const __u32 key = 0;
    if (bpf_map__update_elem(skel->maps.config_map, &key, sizeof(key), &config, sizeof(config), 0)
        != 0) {
        std::cerr << "Failed to update configuration\n";
        knock_bpf__destroy(skel);
        return 1;
    }

    bpf_link* link = bpf_program__attach_xdp(skel->progs.knock, ifindex);
    if (!link) {
        std::cerr << "Failed to attach XDP program\n";
        knock_bpf__destroy(skel);
        return 1;
    }

    std::cout << "Attached XDP program to " << ifname << '\n';
    std::cout << "Waiting for packets (Ctrl+C to exit)...\n";

    while (keep_running) {
        sleep(1);
    }

    bpf_link__destroy(link);
    knock_bpf__destroy(skel);
    std::cout << "Detached XDP program from " << ifname << '\n';

    return 0;
}