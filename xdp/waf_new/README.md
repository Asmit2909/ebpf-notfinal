# XDP WAF

A simple eBPF-based L3/L4 web application firewall that drops:
- malformed packets
- blocklisted IPv4 addresses / subnets
- source IP rate-limit violators

Legitimate traffic is passed up the normal kernel stack to your application.
This repository implements a classic XDP attach-based WAF.

## Repository contents

- `xdp_waf.c`     — eBPF/XDP program loaded into the kernel
- `waf_loader.c`  — userspace loader, map pinning, blocklist load, stats
- `Makefile`      — builds both
- `blocklist.txt` — sample IPv4 blocklist with single IPs and CIDRs

## Requirements

- Linux kernel 5.4+ (5.15+ recommended)
- `clang`, `llvm`
- `libbpf-dev`, `libelf-dev`, `zlib1g-dev`
- `linux-headers-$(uname -r)`
- `bpftool`, `iproute2`, `build-essential`

On Ubuntu/Debian:

```bash
sudo apt update
sudo apt install -y clang llvm libbpf-dev linux-headers-$(uname -r) \
                    libelf-dev zlib1g-dev bpftool iproute2 build-essential
```

Kernel ≥ 5.4 (5.15+ recommended).

## Build

```bash
make
```

This produces:
- `xdp_waf.o`
- `waf_loader`

## Run

> Always test on a VM or a machine with console/IPMI recovery. A bad XDP
> attach or aggressive rate limit can interfere with network access.

Basic usage:

```bash
sudo ./waf_loader -i <iface> -b blocklist.txt -s
```

Replace `<iface>` with your network interface, for example `eth0` or `veth0`.

Force generic/SKB mode:

```bash
sudo ./waf_loader -i <iface> -b blocklist.txt -g
```

### Makefile convenience targets

```bash
make            # build xdp_waf.o and waf_loader
make stats IFACE=<iface>
make clean
```

## What the loader does

`waf_loader` performs these actions:
- loads `xdp_waf.o`
- attaches the XDP program to the selected interface
- pins maps under `/sys/fs/bpf/waf`
- optionally loads an IPv4 blocklist
- prints counters and a latency histogram
- detaches and removes pinned maps on Ctrl-C

## Verify it is active

In another terminal while the program is running:

```bash
ip link show dev <iface>      # shows xdp or xdpgeneric
bpftool prog show             # lists xdp_waf_prog
bpftool map show              # shows maps under /sys/fs/bpf/waf
```

To confirm traffic is processed:

```bash
curl http://localhost
```

## Blocklist format

The blocklist accepts one IPv4 address or CIDR per line.
Lines beginning with `#` are ignored.

Example:

```text
# single address
192.0.2.7

# subnet
203.0.113.0/24
```

## Runtime counters

The program reports these counters:
- `PASS`
- `DROP_MALFORMED`
- `DROP_BLOCK`
- `DROP_RATE`
- `DROP_PORT`

They are summed across CPUs by the loader.

## Tuning

In `xdp_waf.c`:
- `RL_RATE_PER_SEC` — sustained packets/sec per source IP (default `2000`)
- `RL_BURST`        — burst bucket depth (default `4000`)

If `DROP_RATE` rises during normal traffic, increase these values and rebuild.

