
build-bpf: src/vmlinux.h
	clang -g -O2 -target bpf -c src/ping.bpf.c -o src/ping.bpf.o
.PHONY: build-bpf

load-bpf:
	sudo bpftool prog load src/ping.bpf.o /sys/fs/bpf/ping
.PHONY: load-bpf

src/vmlinux.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > src/vmlinux.h

src/ping.skel.h:
	bpftool gen skeleton src/ping.bpf.o > src/ping.skel.h

build: src/ping.skel.h
	mkdir -p build
	clang++ -g -O2 -Isrc -o build/ping src/main.cpp -lbpf -lelf -lz
.PHONY: build

run:
	build/ping eth0
.PHONY: run