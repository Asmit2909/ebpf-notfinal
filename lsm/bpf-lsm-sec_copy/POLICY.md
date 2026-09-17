# BPF LSM Security Tool Policy Configuration Guide

The `policy.yaml` file is the central command center for the **BPF LSM Security Tool**. It allows you to dynamically declare security rules, specify granular enforcement actions, define complex execution ancestry chains, and even compile and inject entirely new eBPF hooks into the Linux kernel on the fly.

Because the daemon employs a high-performance event loop, any modifications you save to `policy.yaml` are detected instantly. The daemon recalculates internal 64-bit FNV-1a hashes, performs an eventual-consistency diff against the running BPF Maps, and safely syncs your new rules directly into the kernel memory space with **zero downtime**.

---

## Table of Contents
1. [The Policies Block](#1-the-policies-block)
   - [Actions](#actions)
   - [Binaries (Process Execution)](#binaries)
   - [Files (I/O Tracing)](#files)
   - [Networks (CIDR & Port Blocking)](#networks)
2. [The Sensors Block (Dynamic Extensibility)](#2-the-sensors-block-extensibility)
   - [LSM Hooks](#lsm-hooks)
   - [XDP Hooks](#xdp-hooks)
   - [Fentry / Fexit](#fentry--fexit)

---

## 1. The `policies` Block

The `policies` block consists of a list of **Policy Groups**. Each group defines a unified `action` and a list of targets (`binaries`, `files`, or `networks`) to apply that action against. 

### Actions
The `action` field dictates the exact response the kernel should take when a rule is matched. The supported actions are:
- `block`: Hard-deny the action at the kernel level by returning `-EPERM` (Permission Denied).
- `kill`: Immediately obliterate the offending process tree by sending `SIGKILL` (or a custom configured `kill_signal`) directly from the kernel to the process before the action can proceed.
- `alert`: Allow the action to succeed, but send a detailed JSON telemetry event back to the userspace daemon via the BPF Ring Buffer (useful for stealth file I/O monitoring or auditing).
- `deceive`: *(Experimental)* Lie to the process. File and execution hooks return `-ENOENT` (No Such File or Directory) so malware believes the path doesn't exist. All four network hooks (`connect`, `bind`, `listen`, `accept`) return `-ECONNREFUSED`, so a scanner sees a closed port rather than a filtered one.
- `allow`: **(Exception List)** Instantly allow the action to succeed and silently bypass any broader blocking rules.

---

### 1. Binaries (`binaries`)

Restricts execution of specific binaries based on path, arguments, and process ancestry.

*   `path` (string, required): The absolute path to the binary. **Wildcard Support:** You can append `*` to the end of a path (e.g., `/usr/bin/*`) to block execution of any binary inside a directory (Prefix Matching). (e.g., `/usr/bin/curl`).
- `only_in_container` (Optional, boolean): If set to `true`, the rule is ignored if the binary runs on the host system. It will only block/kill the binary if it executes inside a Docker/Kubernetes container (detected via PID namespaces).
- `ancestors` (Optional, list of strings): A strict execution chain. The daemon maintains an O(1) stateful LRU map of every running process and its parents. If you specify ancestors, the process is ONLY blocked if it was spawned by that exact chain of parent processes. You can specify up to **8** ancestors.
- `args` (Optional, list of strings): Filters the command-line arguments passed to the binary (Deep Kernel Inspection). The kernel uses a dual-hook tracepoint synchronization to capture `argv` and block execution only if a specific argument is present. You can specify up to **32** blocked arguments.

**Example: Container Escape Prevention**
```yaml
policies:
  - name: "Prevent Container Escapes"
    action: "block"
    binaries:
      - path: "/usr/bin/curl"
        only_in_container: true
        ancestors:
          - "python3"
          - "java"
          - "sshd"
```
*In the example above, `curl` is only blocked if it is running inside a container AND was spawned by a Python script, which was spawned by Java, which was spawned by SSH. A normal user running `curl` on the host will not be blocked.*

---

### 2. Files (`files`)

Restricts file access unconditionally, or based on specific process ancestry (App-Specific File Jails).

*   `path` (string, required): The absolute path to the file or directory. **Wildcard Support:** You can append `*` to the end of a path (e.g., `/etc/*` or `/var/log/*`) to apply the rule to an entire directory (Prefix Matching). Pure suffix wildcards (e.g., `*.log`) are not supported.
*   `ancestors` (Optional, list of strings): A strict execution chain. The daemon maintains an O(1) stateful LRU map of every running process and its parents. If you specify ancestors, the file access is ONLY blocked if the calling process was spawned by that exact chain of parent processes. You can specify up to **8** ancestors.

**Example 1: Global File Blocking**
```yaml
policies:
  - name: "Protect Secrets Globally"
    action: "block"
    files:
      - path: "/var/my_secrets/*"
```

**Example 2: App-Specific File Jails (LFI Defense)**
```yaml
policies:
  - name: "Nginx File Jail"
    action: "block"
    files:
      - path: "/etc/passwd"
        ancestors:
          - "/usr/sbin/nginx"
      - path: "/home/*"
        ancestors:
          - "/usr/sbin/nginx"
```

---

### Networks
The `networks` list targets both **outgoing (egress)** and **incoming (ingress)** connections. Four LSM hooks are enforced:

| Hook | Direction | Fires when | Denying it means |
|---|---|---|---|
| `socket_connect` | egress | a local process dials out | the outbound connection never forms |
| `socket_bind` | ingress | a process claims a local `addr:port` | it cannot squat that port |
| `socket_listen` | ingress | a socket enters `LISTEN` | it never becomes reachable |
| `socket_accept` | ingress | a remote peer connects to us | **no response is ever sent to that peer** |

`socket_accept` is the enforcement point for **outgoing response control**. Because the accept is refused at the LSM layer, the kernel never hands the connection to your server process, so no response bytes are ever emitted to a blocked peer.

**Supported Fields:**
- `ip` (Optional, string): Matches a specific IPv4 or IPv6 address. For `connect` this is the *destination*; for `bind`/`listen` the *local bind address*; for `accept` the *remote peer*.
- `port` (Optional, uint16): Matches a specific port.
- `cidr` (Optional, string): Matches an entire subnet using native kernel Longest-Prefix-Match (e.g., `192.168.0.0/16`).
- `port_range` (Optional, string): Matches a range of ports (e.g., `8000-9000`).
- `direction` (Optional, string): Scopes the rule to specific hooks. See below.

**Direction Scoping (`direction`)**

By default a network rule applies to **every** hook. Set `direction` to narrow it. Accepts a single value or a comma-separated list:

| Value | Expands to |
|---|---|
| `any` (default) | all four hooks |
| `connect` | egress only |
| `bind` / `listen` / `accept` | that single hook |
| `egress` | `connect` |
| `ingress` | `bind`,`listen`,`accept` |

```yaml
- port_range: "4444-4445"
  direction: "bind,listen"     # can't listen on 4444, but may still dial out to it

- cidr: "10.66.0.0/16"
  direction: "accept"          # never respond to this subnet

- port: 8080
  direction: "ingress"         # audit inbound only
```

If `any` appears anywhere in the list it absorbs the rest. An unrecognized value causes that single rule to be skipped with a log warning; the rest of the policy still loads.

> **Backward compatibility:** rules written before `direction` existed have no `direction` field, so they resolve to `any` and continue to apply to `connect` exactly as before — but they now *also* apply to the inbound hooks. If you have an existing rule that should stay egress-only, add `direction: "egress"` explicitly.

**Port semantics on `accept`**

For `accept`, the peer's source port is ephemeral and rarely useful to match on. The rule is therefore evaluated first against the **local service port** (the port your server is listening on), and only then against the peer's source port. This means `- port: 8080, direction: accept` matches *connections arriving at your port 8080*, which is almost always what you want.

**How `port_range` is implemented**

`blocked_ports` is a kernel HASH keyed by a single `u16`; the kernel performs one exact-key lookup and cannot scan a range. The daemon therefore **materializes a range as one map entry per port** at load time. A `port_range: "5555-5556"` inserts two entries. The map holds 65536 entries, so even `0-65535` fits.

> **Caveat — same key, last write wins.** Two rules that resolve to the same map key (e.g. `- port: 4444` in one policy and `port_range: "4444-4445"` in another) will overwrite each other; the rule appearing **later** in `policy.yaml` wins, taking its `action` *and* its `direction` with it. This applies to `action` as well and predates direction scoping. Keep your port rules disjoint, or order them deliberately.

**Logical Combinations (AND / OR):**
By default, defining rules in separate list items creates a **Logical OR**. However, you can freely mix and match fields within the *same* list item to create a **Logical AND** (e.g., applying a port range to a specific CIDR or IP). The kernel resolves these natively using cascaded `BPF_MAP_TYPE_LPM_TRIE` and Hash map lookups.

**Rule Precedence (Exception Lists):**
To support the `action: "allow"` exception-list model, the kernel evaluates network maps in a highly specific cascading order. This ensures that an `allow` exception for a specific server successfully bypasses a broader block rule. The precedence is:
1. Exact IP + Exact Port / Range
2. Exact IP Only
3. CIDR Subnet Match (LPM Trie)
4. Global Port / Range Match

**All four network hooks share this identical cascade.** A candidate rule is only selected if its port range matches *and* its `direction` includes the current hook; otherwise the cascade falls through to the next tier. This means an `allow` exception scoped to `direction: "accept"` will bypass a broader `block` rule on accepts without weakening the same block rule on `connect`.

**Example: Advanced Network Combinations**
```yaml
policies:
  - name: "Block Cryptominers and Specific Subnets"
    action: "block"
    networks:
      - port: 3333                    # Global Logical OR: Blocks port 3333 on ALL IPs
      - port_range: "8000-9000"       # Global Logical OR: Blocks ports 8000-9000 on ALL IPs
      - ip: "192.168.1.100"           # Global Logical OR: Blocks IP 192.168.1.100 on ALL ports
      - cidr: "10.0.0.0/8"
        port_range: "4000-5000"       # Logical AND: Blocks ports 4000-5000 ONLY on the 10.0.0.0/8 subnet
      - ip: "2001:db8::1"
        port: 80                      # Logical AND: Blocks port 80 ONLY on this exact IPv6 address
```

---

## 2. The `sensors` Block (Extensibility)

The `sensors` block is the daemon's most powerful feature. It allows you to inject custom eBPF code directly into the kernel without modifying the Go daemon. You can use this to dynamically hook into almost any part of the Linux kernel or networking stack while the system is live.

**Supported Fields:**
- `name` (Required): A unique identifier for the sensor.
- `type` (Required): The type of hook to attach to. Must be one of:
  - `lsm`: Linux Security Module hooks (over 200+ available, e.g., `socket_connect`, `sb_mount`, `inode_unlink`).
  - `fentry` / `fexit`: Kernel function tracing. Attaches to the entry or exit of almost any function in the kernel (e.g., `vfs_read`, `tcp_sendmsg`).
  - `xdp`: eXpress Data Path. Attaches to raw Network Interface Cards (NICs) to process or drop packets at the driver level before they reach the Linux network stack.
- `hook` (Required): The target of the hook.
  - For `lsm`, this is the hook name (e.g., `socket_connect`).
  - For `fentry`/`fexit`, this is the kernel function name (e.g., `vfs_read`).
  - For `xdp`, this is the network interface name (e.g., `eth0`).
- `code` (Optional): Inline C code. The daemon will automatically wrap this in a boilerplate (including `vmlinux.h`, ringbuffer maps, and GPL licenses) and compile it via `clang` on the fly.
- `object_path` (Optional): The absolute path to a precompiled eBPF ELF object (`.o` file). If specified, the daemon bypasses dynamic compilation and directly loads the ELF object, allowing you to build complex programs externally.

### Example 1: Dynamic C Code (LSM)
```yaml
sensors:
  - name: "custom_socket_logger"
    type: "lsm"
    hook: "socket_connect"
    code: |
      bpf_printk("A socket connection was intercepted!");
      return 0; // Allow the connection
```

### Example 2: Precompiled XDP Object
```yaml
sensors:
  - name: "hardware_packet_dropper"
    type: "xdp"
    hook: "eth0"
    object_path: "/opt/bpf-lsm-sec/sensors/xdp_drop.o"
```

### Example 3: Function Exit Tracing
```yaml
sensors:
  - name: "trace_tcp_sends"
    type: "fexit"
    hook: "tcp_sendmsg"
    code: |
      bpf_printk("TCP message sent!");
      return 0;
```

---

## Conclusion
The daemon automatically polls `policy.yaml` every few seconds for changes. Upon detecting a modification, it orchestrates a zero-downtime hot reload. Simply edit the file, save it, and watch the daemon logs apply the new rules instantly!