#pragma once
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "knock.h"

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
    __type(value, struct knock_config);
} config_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u16);
} target_port_map SEC(".maps");

#define log_info(fmt, ...) bpf_printk("info: " fmt, ##__VA_ARGS__)
#define log_error(fmt, ...) bpf_printk("error: " fmt, ##__VA_ARGS__)
#define log_debug(fmt, ...) bpf_printk("debug: " fmt, ##__VA_ARGS__)

#define MS_TO_NS(ms) (ms * 1000000)