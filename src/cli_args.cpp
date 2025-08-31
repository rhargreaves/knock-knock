#include "cli_args.hpp"
#include "knock.h"
#include <CLI/CLI.hpp>
#include <iostream>
#include <cstdlib>

static constexpr std::string_view VERSION = BUILD_VERSION;

std::optional<cli_args> parse_args(int argc, char** argv)
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

    app.add_option("-s,--session-timeout", args.session_timeout, "Session timeout in milliseconds")
        ->default_val(60000);

    try {
        app.parse(argc, argv);
    } catch (const CLI::ParseError& e) {
        app.exit(e);
        return std::nullopt;
    }

    if (args.sequence.size() > MAX_SEQUENCE_LENGTH) {
        std::cerr << "error: sequence length cannot exceed " << MAX_SEQUENCE_LENGTH << std::endl;
        return std::nullopt;
    }

    return args;
}