#pragma once
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

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

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10000);
    __type(key, __u32); // source IP
    __type(value, struct ip_state);
} ip_tracking_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct port_sequence);
} config_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u16);
} target_port_map SEC(".maps");