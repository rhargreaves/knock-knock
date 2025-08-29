.SHELL := /bin/bash
.ONESHELL:

LIBBPF_A := libbpf/src/libbpf.a
CLI11_INCLUDE := deps/CLI11/include

# PYTEST_ARGS := --capture=no
PYTEST_ARGS :=
PIP_ARGS := --disable-pip-version-check -q


src/vmlinux.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > src/vmlinux.h

src/knock.bpf.o: src/knock.bpf.c src/vmlinux.h
	clang -g -O2 -target bpf -c src/knock.bpf.c -o src/knock.bpf.o
.PHONY: src/knock.bpf.o

src/knock.skel.h: src/knock.bpf.o
	bpftool gen skeleton src/knock.bpf.o > src/knock.skel.h

build: src/knock.skel.h $(LIBBPF_A)
	mkdir -p build
	clang++ -g -O2 -Isrc -I$(CLI11_INCLUDE) -o build/knock src/main.cpp src/bpf_program.cpp \
		$(LIBBPF_A) -lelf -lz
.PHONY: build

load-bpf:
	sudo bpftool prog load src/knock.bpf.o /sys/fs/bpf/knock
.PHONY: load-bpf

run:
	sudo build/knock lo 8080 123 456 789
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
	rm -rf build src/vmlinux.h src/knock.skel.h src/knock.bpf.o
.PHONY: clean