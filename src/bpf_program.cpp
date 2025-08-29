#include "knock.skel.h"
#include "knock.h"
#include <string>
#include <stdexcept>

class BpfProgram {
private:
    knock_bpf* skel = nullptr;
    bpf_link* link = nullptr;
    std::string interface_name;

public:
    BpfProgram()
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

    ~BpfProgram()
    {
        cleanup();
    }

    BpfProgram(const BpfProgram&) = delete;
    BpfProgram& operator=(const BpfProgram&) = delete;
    BpfProgram(BpfProgram&&) = delete;
    BpfProgram& operator=(BpfProgram&&) = delete;

    bool configure(const knock_config& config)
    {
        const __u32 key = 0;
        return bpf_map__update_elem(
                   skel->maps.config_map, &key, sizeof(key), &config, sizeof(config), 0)
            == 0;
    }

    bool attach_xdp(int ifindex, const std::string& interface)
    {
        link = bpf_program__attach_xdp(skel->progs.knock, ifindex);
        if (link) {
            interface_name = interface;
            return true;
        }
        return false;
    }

    void cleanup()
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
};