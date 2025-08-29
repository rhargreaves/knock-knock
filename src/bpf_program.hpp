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
    BpfProgram();
    ~BpfProgram();

    BpfProgram(const BpfProgram&) = delete;
    BpfProgram& operator=(const BpfProgram&) = delete;
    BpfProgram(BpfProgram&&) = delete;
    BpfProgram& operator=(BpfProgram&&) = delete;

    void configure(const knock_config& config);
    void attach_xdp(int ifindex, const std::string& interface);
};