#include "bpf_program.hpp"
#include "bpf_error.hpp"

static void configure_bpf_program(
    const std::unique_ptr<knock_bpf, void (*)(knock_bpf*)>& skel, const knock_config& config)
{
    const __u32 key = 0;
    if (bpf_map__update_elem(skel->maps.config_map, &key, sizeof(key), &config, sizeof(config), 0)
        != 0) {
        throw BpfError("Failed to update BPF configuration");
    }
}

static void load_bpf_program(const std::unique_ptr<knock_bpf, void (*)(knock_bpf*)>& skel)
{
    if (knock_bpf__load(skel.get()) != 0) {
        throw BpfError("Failed to load BPF program");
    }
}

[[nodiscard]] static knock_bpf* open_bpf_program()
{
    auto skel = knock_bpf__open();
    if (!skel) {
        throw BpfError("Failed to open BPF skeleton");
    }
    return skel;
}

BpfProgram::BpfProgram(const knock_config& config)
    : skel(open_bpf_program(), knock_bpf__destroy)
{
    load_bpf_program(skel);
    configure_bpf_program(skel, config);
}

void BpfProgram::attach_xdp(int ifindex, const std::string& interface)
{
    link.reset(bpf_program__attach_xdp(skel->progs.knock, ifindex));
    if (!link) {
        throw BpfError("Failed to attach XDP program to interface " + interface);
    }
}