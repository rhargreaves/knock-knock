#include "bpf_program.hpp"
#include "bpf_error.hpp"

static void configure_bpf_program(knock_bpf* skel, const knock_config& config)
{
    const __u32 key = 0;
    if (bpf_map__update_elem(skel->maps.config_map, &key, sizeof(key), &config, sizeof(config), 0)
        != 0) {
        throw BpfError("Failed to update BPF configuration");
    }
}

static void load_bpf_program(knock_bpf* skel)
{
    if (knock_bpf__load(skel) != 0) {
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
{
    skel.reset(open_bpf_program());
    load_bpf_program(skel.get());
    configure_bpf_program(skel.get(), config);
}

BpfProgram::~BpfProgram() = default;

void BpfProgram::attach_xdp(int ifindex, const std::string& interface)
{
    link.reset(bpf_program__attach_xdp(skel->progs.knock, ifindex));
    if (!link) {
        throw BpfError("Failed to attach XDP program to interface " + interface);
    }
}