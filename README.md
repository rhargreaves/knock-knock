# Knock Knock :punch::punch::door:
[![build](https://github.com/rhargreaves/knock-knock/actions/workflows/build.yml/badge.svg)](https://github.com/rhargreaves/knock-knock/actions/workflows/build.yml)

Port knocking implementation in eBPF

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

### Help

```sh
$ build/knock --help
Knock Knock 👊👊🚪
Port knocking implemention in eBPF


build/knock [OPTIONS] interface target_port sequence...


POSITIONALS:
  interface TEXT REQUIRED     Network interface to monitor (e.g., eth0, lo)
  target_port UINT:INT in [1 - 65535] REQUIRED
                              Target port to protect
  sequence UINT:INT in [1 - 65535] ... REQUIRED
                              Knock sequence ports (space-separated)

OPTIONS:
  -h,     --help              Print this help message and exit
          --version           Display program version information and exit
  -t,     --timeout UINT [5000]
                              Sequence timeout in milliseconds
```