
build-bpf: src/vmlinux.h
	clang -g -O2 -target bpf -c src/ping.bpf.c -o src/ping.bpf.o
.PHONY: build-bpf

load-bpf:
	sudo bpftool prog load src/ping.bpf.o /sys/fs/bpf/ping
.PHONY: load-bpf

src/vmlinux.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > src/vmlinux.h