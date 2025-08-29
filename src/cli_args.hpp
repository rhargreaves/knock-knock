#pragma once
#include <string>
#include <vector>
#include <optional>
#include <cstdint>

struct cli_args {
    std::string interface;
    std::uint16_t target_port;
    std::vector<std::uint16_t> sequence;
    std::uint64_t timeout;
};

std::optional<cli_args> parse_args(int argc, char** argv);