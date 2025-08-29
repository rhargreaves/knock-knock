#include "bpf_program.hpp"
#include <stdexcept>

BpfProgram::BpfProgram()
{
    skel = knock_bpf__open();
    if (!skel) {
        throw std::runtime_error("Failed to open BPF skeleton");
    }

    if (knock_bpf__load(skel) != 0) {
        knock_bpf__destroy(skel);
        skel = nullptr;
        throw std::runtime_error("Failed to load BPF program");
    }
}

BpfProgram::~BpfProgram()
{
    if (link) {
        bpf_link__destroy(link);
        link = nullptr;
    }
    if (skel) {
        knock_bpf__destroy(skel);
        skel = nullptr;
    }
}

bool BpfProgram::configure(const knock_config& config)
{
    const __u32 key = 0;
    return bpf_map__update_elem(
               skel->maps.config_map, &key, sizeof(key), &config, sizeof(config), 0)
        == 0;
}

bool BpfProgram::attach_xdp(int ifindex, const std::string& interface)
{
    link = bpf_program__attach_xdp(skel->progs.knock, ifindex);
    if (link) {
        interface_name = interface;
        return true;
    }
    return false;
}