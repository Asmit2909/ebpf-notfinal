# BPF LSM Security Tool

The BPF LSM Security Tool is an advanced, high-performance, enterprise-grade eBPF security orchestrator built on Linux Security Modules (LSM). It allows you to dynamically block malicious binaries, protect critical files, and intercept network connections globally across the entire operating system, or specifically within containers. 

It is designed with advanced features including deep ancestry checking, deception techniques, bidirectional network mediation, and dynamic sensor hot-reloading.

## Key Features

- **Zero-Downtime Hot Reloading:** Update your YAML policies on the fly. The daemon detects file changes, recalculates internal 64-bit hashes, and seamlessly updates kernel maps without dropping events.
- **Dynamic Sensor Orchestration:** Write raw eBPF C code directly inside `policy.yaml`. The daemon will automatically wrap it, compile it using `clang`, and dynamically inject it into the kernel, linking it to the shared BPF Ring Buffer.
- **Deep Ancestry Enforcement:** Track process trees. Block a binary (like `curl`) *only* if it was spawned by a specific parent chain (like `java` -> `python3`).
- **Deception (Honey-Potting):** Instead of loudly returning `Permission Denied (-EPERM)`, use the `deceive` action to silently return `No Such File or Directory (-ENOENT)` to trick malware.
- **Offline Builds:** All Go dependencies are packaged securely in the `dependencies` folder. No internet access is required to build the daemon.
- **CIDR Subnet & Port Range Blocking:** Uses high-performance eBPF `LPM_TRIE` maps to natively perform Longest-Prefix-Match lookups for subnets. Supports Logical AND network rules (e.g., blocking a specific port *only* on a specific subnet).
- **Full IPv4 & IPv6 Support:** Transparently block network connections regardless of IP version.
- **Bidirectional Network Enforcement:** Mediates both egress (`socket_connect`) and ingress (`socket_bind`, `socket_listen`, `socket_accept`). Denying `socket_accept` refuses the connection before your server process ever sees it, so **no outgoing response is emitted to a blocked peer**.
- **Direction-Scoped Rules:** Any network rule can be scoped with `direction: ingress | egress | connect | bind | listen | accept` (or a comma-separated list). Rules without a `direction` apply to every hook.

## Offline Installation & Build

No downloading or `go mod` fetching is required. All dependencies are vendored locally in the `dependencies` directory.

### Requirements
- **OS:** Linux with eBPF and LSM support (Kernel 5.7+)
- **Packages:** `make`, `clang`, `llvm`, `go`

### Build

To compile the BPF objects and the Go daemon locally:
```bash
make build
```

This will output the `bpf-sec-daemon` binary.

## Running the Daemon

The daemon requires `root` privileges to inject eBPF programs into the kernel.

```bash
sudo ./bpf-sec-daemon
```

By default, the daemon looks for `policy.yaml` in the current working directory. You can optionally specify a custom path:
```bash
sudo ./bpf-sec-daemon /etc/bpf-lsm-sec/production_policy.yaml
```

As the daemon runs, it streams highly structured JSON events to `stdout` via a high-performance BPF Ring Buffer:
```json
{"pid":1331,"action":3,"target":"10.0.0.1:4444","hook":"connect","direction":"egress"}
{"pid":2207,"action":1,"target":"10.66.4.9:51422","hook":"accept","direction":"ingress"}
{"pid":2311,"action":2,"target":"0.0.0.0:4444","hook":"bind","direction":"ingress"}
```

The `direction` field distinguishes egress (we dialed out) from ingress (a peer reached us). It is present on network events only.

## Policy Configuration

The BPF LSM Security Tool is entirely driven by a YAML configuration file. Please refer to [POLICY.md](POLICY.md) for detailed instructions, schemas, and examples on how to write security policies and dynamic sensors.

## Architecture

1. **BPF C Code (`lsm_enforce.bpf.c`)**: The core kernel hooks using `bpf_lsm`. Uses 64-bit FNV-1a hashing for high-speed, collision-resistant string comparisons within the kernel. All four network hooks share a single lookup cascade (`lookup_v4_policy` / `lookup_v6_policy`), so precedence and direction-scoping resolve identically for ingress and egress.
2. **Go Daemon (`main.go`)**: The userspace orchestrator. Built with `cilium/ebpf`, it parses policies, populates BPF Maps, decodes raw kernel byte payloads into JSON, and manages dynamic `clang` compilation.
3. **vmlinux.h**: Statically generated kernel header to ensure the BPF programs compile correctly across different kernel versions without needing local kernel headers installed.

## System Limits (eBPF Maps)

Because this tool relies on high-performance eBPF Kernel Maps (O(1) Hash Maps and Longest-Prefix-Match Tries) instead of linear processing, you can max out the policy engine without slowing down system performance.

### Policy Rule Limits (Total Items)
The following limits apply to the total number of unique items you can define across all your rules in `policy.yaml`:
* **Blocked IP Addresses (IPv4):** `65,536`
* **Blocked IP Addresses (IPv6):** `65,536`
* **Blocked CIDR Subnets (IPv4):** `65,536`
* **Blocked CIDR Subnets (IPv6):** `65,536`
* **Blocked Network Ports:** `65,536`
* **Blocked Binary Paths:** `65,536`
* **Blocked File Paths:** `65,536`

*(Note: If you ever need more than 65k items for a specific category, you can easily increase `max_entries, 65536` in `lsm_enforce.bpf.c` and recompile. It just consumes slightly more RAM).*

### Deep Inspection Limits (Per Rule)
When defining a specific rule for a binary or file, here are the maximum constraints for deep inspection:
* **Max Blocked Arguments (`args`):** `32` unique arguments per rule.
* **Max Ancestor Chain (`ancestors`):** `8` parent processes deep.
* **Max Argument Length:** `128 characters` per argument (arguments longer than this are truncated before hashing).
* **Max File/Binary Path Length:** `256 characters` (Kept highly compact to remain extremely lightweight).

### Stateful Tracking Limits (Concurrent Activity)
The daemon maintains stateful trackers in the kernel to monitor active system behavior. These are the limits of concurrent activity it can track at any given millisecond:
* **Max Tracked Processes:** `65,536` concurrent running processes. (The LRU map will automatically evict the oldest/idle processes to make room if exceeded).
* **Max Tracked File I/O Operations:** `65,536` concurrently open file descriptors being actively monitored for read/write bytes.
* **RingBuffer Event Queue:** `256 KB` of telemetry queue space. If flooded, the kernel will buffer up to 256KB of events before dropping them to protect system stability.

## Troubleshooting

### "invalid go version '1.24.0': must match format 1.23" or "package structs is not in std" / "build constraints exclude all Go files in .../iter"
This project depends on `cilium/ebpf` v0.21.0, which imports the `iter` and `structs` standard-library packages introduced in **Go 1.24**. You therefore need **Go 1.24.0 or newer** installed. Do *not* downgrade the `go` directive in `go.mod` to `1.23` — the build will then fail with `package structs is not in std` and `build constraints exclude all Go files in .../iter`, because those packages don't exist in older toolchains.

Check your version and upgrade if needed:
```bash
go version   # must report go1.24.0 or later
```
If your distro ships an older Go, install a current toolchain from https://go.dev/dl/ (or via `snap install go --classic`) before running `make build`.

### "My policies are not triggering / curl is not blocked!"
By default, some Linux distributions (like Ubuntu 22.04) do not have the `bpf` Linux Security Module enabled in the boot parameters. If the daemon starts successfully but no events are ever blocked or logged, you likely need to enable BPF LSM in your GRUB config.

1. Edit your GRUB configuration file:
   ```bash
   sudo nano /etc/default/grub
   ```
2. Find the `GRUB_CMDLINE_LINUX_DEFAULT` line and append `lsm=lockdown,capability,landlock,yama,apparmor,bpf` to it.
   *(Make sure `bpf` is in the list!)*
3. Update GRUB and reboot:
   ```bash
   sudo update-grub
   sudo reboot
   ```