# Makefile — builds the XDP WAF (Path A): eBPF object + libbpf loader.

CLANG    ?= clang
CC       ?= gcc
IFACE    ?= veth0

ARCH := $(shell uname -m | sed 's/x86_64/x86/;s/aarch64/arm64/;s/ppc64le/powerpc/;s/mips.*/mips/')

# eBPF build flags
BPF_CFLAGS := -O2 -g -Wall -target bpf -D__TARGET_ARCH_$(ARCH)
BPF_CFLAGS += -I/usr/include/$(shell uname -m)-linux-gnu

# Userspace build flags
USER_CFLAGS := -O2 -g -Wall $(shell pkg-config --cflags libbpf)

# Pull the correct libbpf link flags from pkg-config
USER_LDLIBS := $(shell pkg-config --libs libbpf) -lelf -lz

BPF_OBJ := xdp_waf.o
LOADER  := waf_loader
XDP_ATTACH := sudo ip link set dev $(IFACE) xdp obj xdp_waf.o sec xdp
XDP_DETACH := sudo ip link set dev $(IFACE) xdp off

all: $(BPF_OBJ) $(LOADER)

$(BPF_OBJ): xdp_waf.c
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@
	@echo "built $@"

$(LOADER): waf_loader.c
	$(CC) $(USER_CFLAGS) $< -o $@ $(USER_LDLIBS)
	@echo "built $@"

	$(XDP_ATTACH)
load: all
	$(XDP_ATTACH)
	sudo ./$(LOADER) -i $(IFACE) -b blocklist.txt

stats: all
	$(XDP_ATTACH)
	sudo ./$(LOADER) -i $(IFACE) -b blocklist.txt -s

load-generic: all
	$(XDP_ATTACH)
	sudo ./$(LOADER) -i $(IFACE) -b blocklist.txt -g

clean:
	rm -f $(BPF_OBJ) $(LOADER)
	$(XDP_DETACH)

.PHONY: all load stats load-generic clean