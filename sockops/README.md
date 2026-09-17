# sockmap loopback redirect — sockops + sk_msg

This is the **sockops stage** of the larger VajraNaad plan: a self-contained,
runnable proof that a `BPF_MAP_TYPE_SOCKHASH` plus an `sk_msg` verdict program
can short-circuit the loopback TCP/IP path for same-host connections. Two BPF
programs live in one object file:

- **`bpf_sockmap`** (`SEC("sockops")`) — on TCP `ESTABLISHED` (both the active
  and passive side), inserts the socket into the sockhash keyed by its 4-tuple.
- **`bpf_redir`** (`SEC("sk_msg")`) — attached to that same sockhash. On every
  `sendmsg`, it rebuilds the *peer's* key and redirects the payload straight
  onto the peer's ingress queue, so bytes never traverse loopback TCP/IP.

The functional test proves success **by absence**: `iperf3` moves gigabytes
while `tcpdump` on `lo` sees only the handshake and ~zero payload bytes.

---

## Files

| File | What it is |
|---|---|
| `sockmap_redirect.bpf.c` | The two BPF programs + the shared SOCKHASH map. |
| `Makefile` | Builds the object, regenerates `vmlinux.h`, plus `verify`/`run`/`dump`/`clean` targets. |
| `test_sockmap.sh` | Bring-up + functional proof + baseline-vs-redirect throughput. |
| `vmlinux.h` | **Generated** on first build from your kernel's BTF. Not shipped. |
| `sockmap_redirect.bpf.o` | **Generated** build output. Not shipped. |

---

## Prerequisites

You need a **BTF-enabled Linux kernel** and **cgroup v2**. Everything below
assumes a normal modern distro (kernel 5.10+; 5.15+ recommended).

**1. Confirm BTF is present** (required for CO-RE compilation):
```bash
ls /sys/kernel/btf/vmlinux   # must exist
```
If it's missing, your kernel was built without `CONFIG_DEBUG_INFO_BTF=y` and you
cannot CO-RE-compile here — use a kernel that has it.

**2. Confirm cgroup v2 is the unified hierarchy:**
```bash
mount | grep cgroup2   # should show 'cgroup2 on /sys/fs/cgroup'
```
Most current distros default to this. If you're on hybrid/legacy cgroups, boot
with `systemd.unified_cgroup_hierarchy=1`.

**3. Install the toolchain.**

Debian / Ubuntu:
```bash
sudo apt-get update
sudo apt-get install -y clang llvm libbpf-dev linux-tools-common \
                        linux-tools-$(uname -r) iperf3 tcpdump make
```
> `bpftool` ships in `linux-tools-$(uname -r)`. If that package can't be found
> for your exact kernel (common on cloud images), install `bpftool` from your
> distro's generic package or build it from the kernel source tree under
> `tools/bpf/bpftool`.

Fedora / RHEL:
```bash
sudo dnf install -y clang llvm bpftool libbpf-devel iperf3 tcpdump make
```

Arch:
```bash
sudo pacman -S clang llvm bpf iperf3 tcpdump make
```

**4. Verify the tools resolve:**
```bash
clang --version && bpftool version && iperf3 --version && tcpdump --version
```

---

## Build

```bash
make
```

On the first build this will:
1. Generate `vmlinux.h` from `/sys/kernel/btf/vmlinux` (only if absent).
2. Compile `sockmap_redirect.bpf.c` to `sockmap_redirect.bpf.o` with the CO-RE
   flags (`-g -O2 -target bpf -D__TARGET_ARCH_<arch> -mcpu=v3`).
3. Strip DWARF but keep `.BTF` (the loader relocates against `.BTF`, not DWARF).

To force-refresh the kernel header after a kernel upgrade:
```bash
make vmlinux      # deletes and regenerates vmlinux.h
make              # rebuild
```

### Verifier-only check (no attach, fast)
Catches verifier/relocation errors without running the whole test:
```bash
sudo make verify
```
This loads both programs, prints their `prog show` lines, then unpins. If the
verifier rejects anything, you'll see it here with the log.

---

## Run the full test

```bash
sudo make run
# or directly:
sudo ./test_sockmap.sh
```

What it does, in order:
1. **Baseline** — plain loopback `iperf3` for 3s, no BPF loaded.
2. **Load + attach** — pins both progs and the map under `/sys/fs/bpf/sm`,
   attaches `bpf_sockmap` to the test cgroup's `sock_ops`, and attaches
   `bpf_redir` to the map via `msg_verdict`.
3. **Redirect run** — server + client **both inside the test cgroup** (this is
   mandatory — both sockets must be hashed), with `tcpdump` capturing `lo`.
4. **Evidence** — prints sockhash entry count, the `sk_msg` `run_cnt`, and the
   total payload bytes seen on `lo`.

Cleanup runs automatically on exit (detach, unpin, remove cgroup, disable
stats).

---

## How to read the output

A successful run shows four things:

- **Baseline throughput** — some Gbits/sec figure. Your reference point.
- **`sockhash entries (expect >= 2)`** — both directions of the connection got
  inserted. `< 2` means the sockops insert didn't fire for one side (usually a
  cgroup-membership problem — an endpoint wasn't in the cgroup).
- **`sk_msg prog run_cnt (expect > 0)`** — the verdict program actually ran on
  `sendmsg`. `0` means the program isn't attached to the map the sockets are in.
- **`total payload bytes on lo (expect ~0)`** — **the money shot.** Handshake
  and FIN are a few hundred bytes; if redirect is working, you'll see roughly
  that and nothing more, while `iperf3` reported gigabytes. If you instead see
  payload bytes in the gigabytes, redirection is **not** happening and traffic
  fell back to the normal loopback path.

> The redirect run's `iperf3` throughput is **not** the headline metric and can
> even look similar to (or lower than) baseline on `lo`, because loopback is
> already memory-fast. The proof is the *byte absence on `lo`*, not a bigger
> number. On a real cross-NIC or high-loss path the throughput/latency win is
> where it shows up — loopback just makes the mechanism easy to prove.

---

## What was fixed vs. the originally uploaded files

Small but run-blocking:

1. **Filename.** The source was uploaded as `sockmap_redirect_bpf.c` but the
   script (and every convention) expects `sockmap_redirect.bpf.c`. Renamed to
   the canonical `.bpf.c`.
2. **Build path unified.** The old script called `clang` directly and omitted
   `-D__TARGET_ARCH_*` / `-mcpu`, which can break CO-RE relocations on some
   setups. The script now delegates to `make`, so there's exactly one set of
   compile flags.
3. **Robustness in the script** — cgroup-v2 mount check up front, move the shell
   back to the root cgroup before `rmdir` in cleanup, kill stray one-shot
   servers, and don't hard-fail the `run_cnt` grep if stats are off.

Everything else in your script's attach logic was already correct: with
`bpftool prog loadall ... pinmaps "$PIN"`, programs pin under their C function
names (`bpf_sockmap`, `bpf_redir`) and the map pins under `sock_ops_map`, which
is exactly what the attach/detach lines reference.

---

## Correctness notes on the BPF code (read before extending)

The program loads and the loopback proof passes, but there are a few real
sharp edges worth knowing before you push this past a same-host demo:

- **`__u32` ports in the key.** The key stores `sport`/`dport` as `__u32` and
  the code normalizes everything to "network-order port in the low 16 bits."
  That's internally consistent between the two programs (both write the same
  representation), which is all the hash lookup needs. Just don't compare these
  fields against a port you built some other way without matching the exact
  same normalization — that's the classic sockmap footgun and the reason the
  comment block in the source is so emphatic.
- **`family` filter.** Both programs early-out on anything that isn't
  `AF_INET`. IPv6 loopback (`::1`) will **not** be redirected — if you test with
  `iperf3 -6` or a tool that resolves `localhost` to `::1`, you'll see full
  payload on `lo` and conclude (wrongly) that it's broken. The test forces IPv4
  by using `127.0.0.1` explicitly. Keep that in mind.
- **SOCKHASH vs. cgroup scope.** Redirect only happens for sockets that got
  inserted, and insertion only happens for sockets whose process is in the
  attached cgroup at `ESTABLISHED` time. This is why the test runs *both*
  endpoints inside the cgroup. In a real deployment you decide that scope
  deliberately.
- **`max_entries = 65535`.** Fine for a demo. For production sizing this caps
  concurrent hashed sockets; size it to your expected same-host connection
  count.
- **No delete on close.** The map relies on the kernel auto-removing sockets
  from the sockhash when they close (it does, for SOCKHASH). You don't need an
  explicit cleanup program for correctness here, but if you later add per-flow
  state keyed the same way, *that* you'll have to age out yourself.

---

## Troubleshooting

- **`libbpf: prog 'bpf_redir': failed to attach: ...`** — the map isn't the one
  the sockets are in, or `msg_verdict` isn't supported; confirm
  `bpftool feature probe | grep -i sk_msg`.
- **`run_cnt` is 0** — `kernel.bpf_stats_enabled` must be 1 (the script sets it).
  Also means the verdict prog didn't run: check both endpoints are in the cgroup.
- **payload bytes on `lo` are large** — redirect fell back. Most common causes:
  traffic went over `::1` (IPv6, see above), or only one endpoint was in the
  cgroup so only one direction hashed.
- **`bpftool: command not found`** — install `linux-tools-$(uname -r)` or build
  bpftool from the kernel tree.
- **`/sys/kernel/btf/vmlinux` missing** — kernel lacks BTF; you can't CO-RE
  build. Use a BTF-enabled kernel.

---

## Cleanup (manual, if a run was interrupted)

```bash
sudo bpftool cgroup detach /sys/fs/cgroup/sockmap_test sock_ops \
     pinned /sys/fs/bpf/sm/bpf_sockmap 2>/dev/null
sudo rm -rf /sys/fs/bpf/sm
sudo rmdir /sys/fs/cgroup/sockmap_test 2>/dev/null
sudo sysctl -w kernel.bpf_stats_enabled=0
```
