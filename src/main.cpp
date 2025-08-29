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
#include <CLI/CLI.hpp>
#include "knock.h"
#include "bpf_program.hpp"

static volatile sig_atomic_t keep_running = 1;

static constexpr std::string_view VERSION = "1.0.0";

void signal_handler(int sig) noexcept
{
    keep_running = 0;
}

struct cli_args {
    std::string interface;
    __u16 target_port;
    std::vector<__u16> sequence;
    __u64 timeout;
};

static std::optional<cli_args> parse_args(int argc, char** argv)
{
    CLI::App app { "Knock Knock 👊👊🚪\nPort knocking implemention in eBPF" };

    app.add_flag_callback(
        "--version",
        []() {
            std::cout << VERSION << std::endl;
            exit(0);
        },
        "Display program version information and exit");

    cli_args args;
    app.add_option("interface", args.interface, "Network interface to attach to (e.g., eth0, lo)")
        ->required();

    app.add_option("target_port", args.target_port, "Port to protect")
        ->required()
        ->check(CLI::Range(1, 65535));

    app.add_option("sequence", args.sequence, "Knock sequence ports (space-separated)")
        ->required()
        ->check(CLI::Range(1, 65535));

    app.add_option("-t,--timeout", args.timeout, "Sequence timeout in milliseconds")
        ->default_val(5000);

    try {
        app.parse(argc, argv);
    } catch (const CLI::ParseError& e) {
        app.exit(e);
        return std::nullopt;
    }

    if (args.sequence.size() > MAX_SEQUENCE_LENGTH) {
        std::cerr << "Error: sequence length cannot exceed " << MAX_SEQUENCE_LENGTH << std::endl;
        return std::nullopt;
    }

    return args;
}

static void print_config(const struct knock_config& config)
{
    std::cout << "Target port: " << config.target_port << '\n';
    std::cout << "Knock sequence: ";
    for (int i = 0; i < config.seq.length; i++) {
        std::cout << config.seq.ports[i] << ' ';
    }
    std::cout << '\n';
    std::cout << "Timeout: " << config.seq.timeout_ms << " ms\n";
}

static bool set_memory_limit()
{
    struct rlimit r = { RLIM_INFINITY, RLIM_INFINITY };
    if (setrlimit(RLIMIT_MEMLOCK, &r) != 0) {
        std::cerr << "Failed to set memory lock limit: " << std::system_category().message(errno)
                  << '\n';
        return false;
    }
    return true;
}

int main(int argc, char** argv)
{
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    auto args = parse_args(argc, argv);
    if (!args) {
        return EXIT_FAILURE;
    }

    int ifindex = if_nametoindex(args->interface.c_str());
    if (!ifindex) {
        std::cerr << "Failed to get interface index for " << args->interface << '\n';
        return EXIT_FAILURE;
    }

    if (!set_memory_limit()) {
        return EXIT_FAILURE;
    }

    try {
        BpfProgram bpf_program;

        struct knock_config config = { 0 };
        config.target_port = args->target_port;
        config.seq.length = args->sequence.size();
        config.seq.timeout_ms = args->timeout;
        for (size_t i = 0; i < args->sequence.size(); i++) {
            config.seq.ports[i] = args->sequence[i];
        }
        print_config(config);

        if (!bpf_program.configure(config)) {
            std::cerr << "Failed to update configuration\n";
            return EXIT_FAILURE;
        }

        if (!bpf_program.attach_xdp(ifindex, args->interface)) {
            std::cerr << "Failed to attach XDP program\n";
            return EXIT_FAILURE;
        }

        std::cout << "Attached XDP program to " << args->interface << '\n';
        std::cout << "Waiting for packets (Ctrl+C to exit)...\n";

        while (keep_running) {
            sleep(1);
        }

        std::cout << "Detached XDP program from " << args->interface << '\n';
        return EXIT_SUCCESS;

    } catch (const std::exception& e) {
        std::cerr << "BPF error: " << e.what() << '\n';
        return EXIT_FAILURE;
    }
}