#include <bpf/libbpf.h>
#include <net/if.h>
#include <sys/resource.h>
#include <unistd.h>
#include <signal.h>
#include <iostream>
#include <vector>
#include <CLI/CLI.hpp>
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

    CLI::App app { "Knock knock! Port knocking implemention in eBPF" };

    app.add_flag_callback(
        "--version",
        []() {
            std::cout << "1.0.0" << std::endl;
            exit(0);
        },
        "Display program version information and exit");

    std::string interface;
    __u16 target_port = 0;
    std::vector<__u16> sequence;
    __u64 timeout = 5000;

    app.add_option("interface", interface, "Network interface to monitor (e.g., eth0, lo)")
        ->required();

    app.add_option("target_port", target_port, "Target port to protect")
        ->required()
        ->check(CLI::Range(1, 65535));

    app.add_option("sequence", sequence, "Knock sequence ports (space-separated)")
        ->required()
        ->check(CLI::Range(1, 65535));

    app.add_option("-t,--timeout", timeout, "Sequence timeout in milliseconds")->default_val(5000);

    try {
        app.parse(argc, argv);
    } catch (const CLI::ParseError& e) {
        return app.exit(e);
    }

    if (sequence.size() > MAX_SEQUENCE_LENGTH) {
        std::cerr << "Error: sequence length cannot exceed " << MAX_SEQUENCE_LENGTH << std::endl;
        return 1;
    }

    int ifindex = if_nametoindex(interface.c_str());
    if (!ifindex) {
        std::cerr << "Failed to get interface index for " << interface << '\n';
        return 1;
    }

    struct knock_config config = { 0 };
    config.target_port = target_port;
    config.seq.length = sequence.size();
    config.seq.timeout_ms = timeout;
    for (size_t i = 0; i < sequence.size(); i++) {
        config.seq.ports[i] = sequence[i];
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

    std::cout << "Attached XDP program to " << interface << '\n';
    std::cout << "Waiting for packets (Ctrl+C to exit)...\n";

    while (keep_running) {
        sleep(1);
    }

    bpf_link__destroy(link);
    knock_bpf__destroy(skel);
    std::cout << "Detached XDP program from " << interface << '\n';

    return 0;
}