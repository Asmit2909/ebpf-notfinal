# Makefile — sockmap loopback-redirect (sockops + sk_msg)
#
# Targets:
#   make            # build the BPF object (default)
#   make vmlinux    # (re)generate vmlinux.h from the running kernel's BTF
#   make verify     # load the object and run the verifier WITHOUT attaching
#   make run        # run the full functional + throughput test (needs root)
#   make dump       # show the pinned map + prog after a run
#   make clean      # remove build artifacts
#   make distclean  # clean + also remove generated vmlinux.h
#
# Requirements on the HOST (not needed to just read this):
#   clang >= 11, llvm-strip, bpftool, a BTF-enabled kernel
#   (CONFIG_DEBUG_INFO_BTF=y — check: ls /sys/kernel/btf/vmlinux)

# ---- toolchain --------------------------------------------------------------
CLANG      ?= clang
LLVM_STRIP ?= llvm-strip
BPFTOOL    ?= bpftool

# ---- files ------------------------------------------------------------------
BPF_SRC    := sockmap_redirect.bpf.c
BPF_OBJ    := sockmap_redirect.bpf.o
VMLINUX_H  := vmlinux.h
TEST       := test_sockmap.sh

# ---- target arch for the bpf target -----------------------------------------
# clang wants the *linux* arch name; uname -m gives x86_64 which we map.
ARCH := $(shell uname -m | sed 's/x86_64/x86/' \
                         | sed 's/aarch64/arm64/' \
                         | sed 's/ppc64le/powerpc/' \
                         | sed 's/mips.*/mips/' \
                         | sed 's/s390x/s390/')

# ---- clang flags ------------------------------------------------------------
# -g is REQUIRED: BPF CO-RE relocations are emitted into DWARF/BTF, so an
# unstripped object with debug info is what the loader relocates against.
CFLAGS := -g -O2 -Wall -Werror \
          -target bpf \
          -D__TARGET_ARCH_$(ARCH) \
          -mcpu=v3 \
          -I.

.PHONY: all vmlinux verify run dump clean distclean

all: $(BPF_OBJ)

# Generate the kernel type header from the running kernel's BTF.
# Only regenerated if missing; delete it (or `make distclean`) to refresh.
$(VMLINUX_H):
	@echo "  GEN     $(VMLINUX_H)  (from /sys/kernel/btf/vmlinux)"
	@if [ ! -e /sys/kernel/btf/vmlinux ]; then \
		echo "ERROR: /sys/kernel/btf/vmlinux missing — kernel built without CONFIG_DEBUG_INFO_BTF."; \
		echo "       You cannot CO-RE-compile here. Build on a BTF-enabled kernel."; \
		exit 1; \
	fi
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

$(BPF_OBJ): $(BPF_SRC) $(VMLINUX_H)
	@echo "  CLANG   $@   (arch=$(ARCH))"
	$(CLANG) $(CFLAGS) -c $(BPF_SRC) -o $@
	@echo "  STRIP   $@   (drop DWARF, keep .BTF)"
	$(LLVM_STRIP) -g $@
	@echo "  OK      built $@"

# Explicit target if you want to force-refresh the header.
vmlinux:
	@rm -f $(VMLINUX_H)
	@$(MAKE) --no-print-directory $(VMLINUX_H)

# Load into the kernel and run the verifier, but do not attach to anything.
# Fast way to catch verifier/relocation errors without the whole test.
verify: $(BPF_OBJ)
	@[ "$$(id -u)" -eq 0 ] || { echo "run as root: sudo make verify"; exit 1; }
	@echo "  LOAD    $(BPF_OBJ)  -> /sys/fs/bpf/sm_verify (verifier check only)"
	@rm -rf /sys/fs/bpf/sm_verify
	$(BPFTOOL) prog loadall $(BPF_OBJ) /sys/fs/bpf/sm_verify pinmaps /sys/fs/bpf/sm_verify
	@echo "  OK      verifier accepted both programs"
	@$(BPFTOOL) prog show pinned /sys/fs/bpf/sm_verify/bpf_sockmap
	@$(BPFTOOL) prog show pinned /sys/fs/bpf/sm_verify/bpf_redir
	@rm -rf /sys/fs/bpf/sm_verify
	@echo "  CLEAN   unpinned verify artifacts"

run: $(BPF_OBJ) $(TEST)
	@[ "$$(id -u)" -eq 0 ] || { echo "run as root: sudo make run"; exit 1; }
	@chmod +x $(TEST)
	./$(TEST)

dump:
	@$(BPFTOOL) map  dump pinned /sys/fs/bpf/sm/sock_ops_map 2>/dev/null || echo "map not pinned (run first)"
	@echo "---"
	@$(BPFTOOL) prog show pinned /sys/fs/bpf/sm/bpf_redir   2>/dev/null || echo "prog not pinned (run first)"

clean:
	@rm -f $(BPF_OBJ)
	@echo "  CLEAN   removed $(BPF_OBJ)"

distclean: clean
	@rm -f $(VMLINUX_H)
	@echo "  CLEAN   removed $(VMLINUX_H)"
