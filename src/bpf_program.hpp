#pragma once
#include "knock.skel.h"
#include "knock.h"
#include <string>
#include <memory>

struct BpfLinkDeleter {
    void operator()(bpf_link* link)
    {
        if (link)
            bpf_link__destroy(link);
    }
};

class BpfProgram {
private:
    std::unique_ptr<knock_bpf, void (*)(knock_bpf*)> skel { nullptr, knock_bpf__destroy };
    std::unique_ptr<bpf_link, BpfLinkDeleter> link;

public:
    explicit BpfProgram(const knock_config& config);
    ~BpfProgram();

    BpfProgram(const BpfProgram&) = delete;
    BpfProgram& operator=(const BpfProgram&) = delete;
    BpfProgram(BpfProgram&&) = delete;
    BpfProgram& operator=(BpfProgram&&) = delete;

    void attach_xdp(int ifindex, const std::string& interface);
};