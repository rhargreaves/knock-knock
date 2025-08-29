#pragma once
#include <string>
#include <vector>
#include <optional>
#include <linux/types.h>

struct cli_args {
    std::string interface;
    __u16 target_port;
    std::vector<__u16> sequence;
    __u64 timeout;
};

std::optional<cli_args> parse_args(int argc, char** argv);