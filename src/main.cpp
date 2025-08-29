#include <bpf/libbpf.h>
#include <cstdlib>
#include <net/if.h>
#include <string>
#include <sys/resource.h>
#include <unistd.h>
#include <signal.h>
#include <iostream>
#include <vector>
#include <optional>
#include <system_error>
#include "knock.h"
#include "bpf_program.hpp"
#include "cli_args.hpp"

static volatile sig_atomic_t keep_running = 1;

void signal_handler(int sig) noexcept
{
    keep_running = 0;
}

static void print_config(const struct knock_config& config)
{
    std::cout << "target port: " << config.target_port << '\n';
    std::cout << "knock sequence: ";
    for (int i = 0; i < config.seq.length; i++) {
        std::cout << config.seq.ports[i] << ' ';
    }
    std::cout << '\n';
    std::cout << "timeout: " << config.seq.timeout_ms << " ms\n";
}

static void set_memory_limit()
{
    struct rlimit r = { RLIM_INFINITY, RLIM_INFINITY };
    if (setrlimit(RLIMIT_MEMLOCK, &r) != 0) {
        throw std::system_error(errno, std::system_category(), "Failed to set memory lock limit");
    }
}

static int get_interface_index(const std::string& interface_name)
{
    int ifindex = if_nametoindex(interface_name.c_str());
    if (!ifindex) {
        throw std::system_error(
            errno, std::system_category(), "failed to get interface index for " + interface_name);
    }
    return ifindex;
}

static void parse_config(const cli_args& args, struct knock_config& config)
{
    config.target_port = args.target_port;
    config.seq.length = args.sequence.size();
    config.seq.timeout_ms = args.timeout;
    for (size_t i = 0; i < args.sequence.size(); i++) {
        config.seq.ports[i] = args.sequence[i];
    }
}

int main(int argc, char** argv)
{
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    auto args = parse_args(argc, argv);
    if (!args) {
        return EXIT_FAILURE;
    }

    struct knock_config config;
    parse_config(*args, config);
    print_config(config);

    try {
        set_memory_limit();
        int ifindex = get_interface_index(args->interface);
        BpfProgram bpf_program;
        bpf_program.configure(config);
        bpf_program.attach_xdp(ifindex, args->interface);

        std::cout << "attached XDP program to " << args->interface << '\n';
        std::cout << "waiting for packets (Ctrl+C to exit)...\n";

        while (keep_running) {
            sleep(1);
        }

        std::cout << "detached XDP program from " << args->interface << '\n';
        return EXIT_SUCCESS;

    } catch (const std::exception& e) {
        std::cerr << "error: " << e.what() << '\n';
        return EXIT_FAILURE;
    }
}