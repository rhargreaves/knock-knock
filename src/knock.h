#pragma once

#if !defined(__VMLINUX_H__)
#include <linux/types.h>
#include <stdbool.h>
#endif

#define MAX_SEQUENCE_LENGTH 10

struct port_sequence {
    __u16 ports[MAX_SEQUENCE_LENGTH];
    __u8 length;
    __u64 timeout_ms;
};

struct ip_state {
    __u8 sequence_step;
    __u64 last_packet_time;
    bool sequence_complete;
};

struct knock_config {
    __u16 target_port;
    struct port_sequence seq;
};
