#pragma once
#include "knock.skel.h"
#include "knock.h"
#include <string>

class BpfProgram {
private:
    knock_bpf* skel = nullptr;
    bpf_link* link = nullptr;
    std::string interface_name;

public:
    explicit BpfProgram(const knock_config& config);
    ~BpfProgram();

    BpfProgram(const BpfProgram&) = delete;
    BpfProgram& operator=(const BpfProgram&) = delete;
    BpfProgram(BpfProgram&&) = delete;
    BpfProgram& operator=(BpfProgram&&) = delete;

    void attach_xdp(int ifindex, const std::string& interface);
};