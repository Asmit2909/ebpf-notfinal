#!/bin/bash

# Exit on error
set -e

echo "[*] Compiling xdp_model.c into BPF object..."
# Compile into eBPF object file.
# Note: Requires clang and libbpf-dev to be installed in WSL (sudo apt install clang llvm libbpf-dev)
clang -O2 -g -target bpf -I/usr/include/x86_64-linux-gnu -c xdp_model.c -o xdp_model.o

echo "[*] Unloading any existing XDP programs from 'veth0'..."
# We use 'veth0' for Mininet testing (veth pairs require xdpgeneric)
sudo ip link set dev enp0s3 xdp off 2>/dev/null || true

echo "[*] Loading new XDP program to 'veth0' (xdpgeneric mode)..."
sudo ip link set dev enp0s3 xdp obj xdp_model.o sec xdp

echo "[+] Successfully loaded! Your eBPF ML model is now running in the kernel."
echo "    You can view kernel logs with: sudo cat /sys/kernel/debug/tracing/trace_pipe"
