# Knock Knock :punch::punch::door:
[![build](https://github.com/rhargreaves/knock-knock/actions/workflows/build.yml/badge.svg)](https://github.com/rhargreaves/knock-knock/actions/workflows/build.yml)

Port knocking implementation in eBPF

## Features

* Protects TCP ports using port knocking, dropping packets until the correct sequence of UDP packets is received
* A sequence of up to 10 UDP packets can be used to protect a port
* Configurable sequence timeout resets the sequence after a period of time
* Configurable session timeout resets the session (blocks packets again) after a period of time

## Components

* Kernel-space BPF program (`knock.bpf.c` et al)
* User-space BPF program loader & configurator CLI tool (`main.cpp` et al)
* Acceptance tests (`test_knock.py` et al)

## Getting Started

Use the Dev Container as the main development environment.

### Build

1. Initialize submodules: `git submodule update --init --recursive`
2. Build the program:

```sh
make build
```

### Test

```sh
make test
```

## Usage

Run as root:

```
build/knock <interface> <target_port> <sequence> <options>
```

* `interface`: Network interface to attach to (e.g., `eth0`, `lo`)
* `target_port`: Port to protect
* `sequence`: Knock sequence ports (space-separated)
* `options`: Optional arguments:
  * `-t`, `--timeout`: Sequence timeout in milliseconds
  * `-s`, `--session-timeout`: Session timeout in milliseconds

Use `--help` to see all options.

## Examples

### Example 1

* Attach to interface `eth0`
* Protect port 8080 with a sequence of 123, 456, 789
* Sequence timeout is 5 seconds (default)
* Session timeout is 60 seconds (default)

```sh
build/knock eth0 8080 123 456 789
```

### Example 2

* Attach to interface `eth0`
* Protect port 8080 with a sequence of 1111, 2222, 3333, 4444
* Sequence timeout is 5 seconds
* Session timeout is 1 hour

```sh
build/knock eth0 8080 1111 2222 3333 4444 -t 5000 -s 3600000
```

## Logging

Program logs various events to the kernel trace buffer. To view the trace, run (as root):

```sh
cat /sys/kernel/debug/tracing/trace_pipe
```