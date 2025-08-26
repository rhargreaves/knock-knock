.SHELL := /bin/bash
.ONESHELL:

LIBBPF_A := libbpf/src/libbpf.a

# PYTEST_ARGS := --capture=no
PYTEST_ARGS :=
PIP_ARGS := --disable-pip-version-check -q


src/vmlinux.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > src/vmlinux.h

src/ping.bpf.o: src/ping.bpf.c src/vmlinux.h
	clang -g -O2 -target bpf -c src/ping.bpf.c -o src/ping.bpf.o
.PHONY: src/ping.bpf.o

src/ping.skel.h: src/ping.bpf.o
	bpftool gen skeleton src/ping.bpf.o > src/ping.skel.h

build: src/ping.skel.h $(LIBBPF_A)
	mkdir -p build
	clang++ -g -O2 -Isrc -o build/ping src/main.cpp \
		$(LIBBPF_A) -lelf -lz
.PHONY: build

load-bpf:
	sudo bpftool prog load src/ping.bpf.o /sys/fs/bpf/ping
.PHONY: load-bpf

run:
	sudo build/ping lo
.PHONY: run

lint-tests:
	source .venv/bin/activate
	pip3 install $(PIP_ARGS) -r test/requirements.txt
	ruff check --fix test/
	ruff format test/
	deactivate
.PHONY: lint-tests

test: build lint-tests
	source .venv/bin/activate
	pip3 install $(PIP_ARGS) -r test/requirements.txt
	sudo pytest $(PYTEST_ARGS)
	deactivate
.PHONY: test

print-trace:
	sudo cat /sys/kernel/debug/tracing/trace_pipe
.PHONY: print-trace

clean:
	rm -rf build
	-sudo pkill -f "build/ping" 2>/dev/null
	-sudo ip link show | grep -o '^[0-9]*: [^:]*' | while read line; do \
		iface=$$(echo $$line | cut -d' ' -f2); \
		sudo ip link set dev $$iface xdp off 2>/dev/null; \
	done
	-sudo rm -f /sys/fs/bpf/ping 2>/dev/null
.PHONY: clean