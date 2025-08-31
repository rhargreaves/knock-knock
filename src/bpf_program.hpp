#pragma once
#include "knock.skel.h"
#include "knock.h"
#include <string>
#include <memory>
#include <functional>

class BpfProgram {
private:
    std::unique_ptr<knock_bpf, void (*)(knock_bpf*)> skel { nullptr, knock_bpf__destroy };
    std::unique_ptr<bpf_link, std::function<void(bpf_link*)>> link { nullptr, [](bpf_link* l) {
                                                                        if (l)
                                                                            bpf_link__destroy(l);
                                                                    } };

public:
    explicit BpfProgram(const knock_config& config);
    ~BpfProgram() = default;

    BpfProgram(const BpfProgram&) = delete;
    BpfProgram& operator=(const BpfProgram&) = delete;
    BpfProgram(BpfProgram&&) = delete;
    BpfProgram& operator=(BpfProgram&&) = delete;

    void attach_xdp(int ifindex, const std::string& interface);
};