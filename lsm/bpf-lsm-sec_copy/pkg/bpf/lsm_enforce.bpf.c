//go:build ignore
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define MAX_ENTRIES 65536
// Hot-cache capacity for the runtime auto-blocklist. Bounded on purpose: the
// permanent record lives in userspace, so this only sizes the in-kernel fast
// path. LRU evicts the coldest entry when full.
#define DYNAMIC_BLOCKLIST_MAX 65536
#define MAX_ANCESTORS 8
#define MAX_ARGS 32
#define MAX_PATH_LEN 256
#define MAX_ARG_LEN 128
#define FNV_OFFSET_BASIS 14695981039346656037ULL
#define FNV_PRIME 1099511628211ULL


#define EPERM  1
#define ENOENT 2
#define AF_INET 2
#define AF_INET6 10

#define ACTION_BLOCK 1
#define ACTION_KILL  2
#define ACTION_ALERT 3
#define ACTION_DECEIVE 4
#define ACTION_ALLOW 5

// Direction bitmask for scoping a network rule to specific hooks.
// DIR_ANY (0) means the rule applies to every network hook.
#define DIR_ANY     0
#define DIR_CONNECT (1 << 0)  // egress: we dial out
#define DIR_BIND    (1 << 1)  // ingress: we claim a local addr:port
#define DIR_LISTEN  (1 << 2)  // ingress: we enter LISTEN
#define DIR_ACCEPT  (1 << 3)  // ingress: a peer connects to us
#define DIR_INGRESS (DIR_BIND | DIR_LISTEN | DIR_ACCEPT)
#define DIR_EGRESS  (DIR_CONNECT)

char LICENSE[] SEC("license") = "GPL";

struct policy_val {
    __u32 action;
    __u32 only_in_container;
    __u32 block_unconditionally;
    __u32 kill_signal;
    __u16 min_port;
    __u16 max_port;
    // Bitmask of DIR_* flags gating which network hooks this rule applies to.
    // 0 is treated as "any direction" for backward compatibility with rules
    // populated before this field existed. Occupies what was previously
    // alignment padding, so sizeof(struct policy_val) is unchanged.
    __u32 direction_mask;
    __u64 ancestor_hashes[8];
    __u64 blocked_arg_hashes[32];
};

struct process_info {
    __u64 exe_hash;
    __u64 ancestors[8];
};

struct exec_args {
    __u64 arg_hashes[32];
};

struct file_stat {
    __u64 bytes_read;
    __u64 bytes_written;
    char filename[128];
};

struct event {
    __u32 pid;
    __u32 action;
    char target[256];
    char hook[16];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, __u32); // PID
    __type(value, struct process_info);
} processes SEC(".maps");

struct path_buf {
    char data[256];
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct path_buf);
} path_buffer SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct process_info);
} process_info_buffer SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct file_stat);
} stat_buffer SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, __u32); // PID
    __type(value, struct exec_args);
} exec_args_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, __u64); // file pointer
    __type(value, struct file_stat);
} file_stats SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, __u64);
    __type(value, struct policy_val);
} blocked_binaries SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, __u64);
    __type(value, struct policy_val);
} blocked_files SEC(".maps");

struct path_lpm_key {
    __u32 prefixlen;
    char data[256];
};

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, struct path_lpm_key);
    __type(value, struct policy_val);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} blocked_binaries_lpm SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, struct path_lpm_key);
    __type(value, struct policy_val);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} blocked_files_lpm SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct path_lpm_key);
} lpm_key_buffer SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, __u16);
    __type(value, struct policy_val);
} blocked_ports SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, __u32);
    __type(value, struct policy_val);
} blocked_ips SEC(".maps");

struct ipv6_key {
    unsigned char addr[16];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, struct ipv6_key);
    __type(value, struct policy_val);
} blocked_ips_v6 SEC(".maps");

struct ipv4_network_key {
    __u32 ip;
    __u16 port;
};

struct ipv6_network_key {
    unsigned char ip[16];
    __u16 port;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, struct ipv4_network_key);
    __type(value, struct policy_val);
} blocked_ipv4_networks SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, struct ipv6_network_key);
    __type(value, struct policy_val);
} blocked_ipv6_networks SEC(".maps");

struct ipv4_lpm_key {
    __u32 prefixlen;
    __u32 data;
};

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, struct ipv4_lpm_key);
    __type(value, struct policy_val);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} blocked_ipv4_cidr SEC(".maps");

struct ipv6_lpm_key {
    __u32 prefixlen;
    __u8 data[16];
};

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, struct ipv6_lpm_key);
    __type(value, struct policy_val);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} blocked_ipv6_cidr SEC(".maps");

/*
 * Dynamic auto-blocklist (IPv4 / IPv6).
 *
 * Populated at RUNTIME by userspace when the XDP/ML sensor flags an IP — this
 * is SEPARATE from the policy.yaml blocklists above, which stay authoritative
 * plain HASHes with no eviction.
 *
 * LRU_HASH here is deliberate and SAFE, unlike on the policy blocklist:
 *   - This map is only a HOT CACHE of auto-flagged IPs worth checking inline.
 *   - Userspace holds the permanent, unbounded record on disk. Every IP is
 *     written to that permanent list BEFORE it is pushed here, so an LRU
 *     eviction never loses information — the coldest (least-recently-hit)
 *     auto-block simply drops out of the fast path while remaining on record.
 *   - A re-offending evicted IP gets re-flagged by the sensor and re-injected,
 *     so it becomes hot again. Attackers cannot permanently flush their block.
 *
 * The value is a policy_val so the same enforce_policy()/action machinery
 * applies (block / kill / alert / deceive), and the same direction gate works.
 */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, DYNAMIC_BLOCKLIST_MAX);
    __type(key, __u32);
    __type(value, struct policy_val);
} autoblock_v4 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, DYNAMIC_BLOCKLIST_MAX);
    __type(key, struct ipv6_key);
    __type(value, struct policy_val);
} autoblock_v6 SEC(".maps");

static __always_inline bool is_policy_valid(struct policy_val *policy, __u16 port) {
    if (!policy) return false;
    if (policy->min_port == 0 && policy->max_port == 0) return true;
    return (port >= policy->min_port && port <= policy->max_port);
}

/*
 * Shared network-policy cascade. Mirrors the exact precedence documented in
 * POLICY.md and already implemented inline in restrict_connect():
 *   1. Exact IP + Exact Port / Range
 *   2. Exact IP Only
 *   3. CIDR Subnet Match (LPM Trie)
 *   4. Global Port / Range Match
 * Reused by the inbound hooks (bind / listen / accept) so all four network
 * enforcement points resolve rules identically.
 */
/*
 * A rule applies to this hook if it declared no direction (legacy / "any")
 * or explicitly included this hook's bit.
 */
static __always_inline bool dir_matches(struct policy_val *policy, __u32 dir) {
    if (!policy) return false;
    if (policy->direction_mask == DIR_ANY) return true;
    return (policy->direction_mask & dir) != 0;
}

/* A candidate is usable only if the port range matches AND the direction matches. */
static __always_inline bool policy_applies(struct policy_val *policy, __u16 port, __u32 dir) {
    return is_policy_valid(policy, port) && dir_matches(policy, dir);
}

static __always_inline struct policy_val *lookup_v4_policy(__u32 ip, __u16 port, __u32 dir) {
    // Dynamic auto-blocklist first. A hit here also bumps the LRU recency of
    // this entry (bpf_map_lookup_elem touches it), so actively-offending IPs
    // stay hot and are not the ones evicted under pressure.
    struct policy_val *policy = bpf_map_lookup_elem(&autoblock_v4, &ip);
    if (policy_applies(policy, port, dir)) {
        return policy;
    }

    struct ipv4_network_key net_key = { .ip = ip, .port = port };
    policy = bpf_map_lookup_elem(&blocked_ipv4_networks, &net_key);

    if (!policy_applies(policy, port, dir)) {
        policy = bpf_map_lookup_elem(&blocked_ips, &ip);
    }
    if (!policy_applies(policy, port, dir)) {
        struct ipv4_lpm_key cidr_key = { .prefixlen = 32, .data = ip };
        policy = bpf_map_lookup_elem(&blocked_ipv4_cidr, &cidr_key);
    }
    if (!policy_applies(policy, port, dir)) {
        policy = bpf_map_lookup_elem(&blocked_ports, &port);
    }
    if (!policy_applies(policy, port, dir)) {
        return NULL;
    }
    return policy;
}

static __always_inline struct policy_val *lookup_v6_policy(struct ipv6_key *ip_key, __u16 port, __u32 dir) {
    // Dynamic auto-blocklist first (see v4 note on LRU recency).
    struct policy_val *policy = bpf_map_lookup_elem(&autoblock_v6, ip_key);
    if (policy_applies(policy, port, dir)) {
        return policy;
    }

    struct ipv6_network_key net_key = {};
    __builtin_memcpy(&net_key.ip, ip_key->addr, 16);
    net_key.port = port;

    policy = bpf_map_lookup_elem(&blocked_ipv6_networks, &net_key);

    if (!policy_applies(policy, port, dir)) {
        policy = bpf_map_lookup_elem(&blocked_ips_v6, ip_key);
    }
    if (!policy_applies(policy, port, dir)) {
        struct ipv6_lpm_key cidr_key = {};
        cidr_key.prefixlen = 128;
        __builtin_memcpy(&cidr_key.data, ip_key->addr, 16);
        policy = bpf_map_lookup_elem(&blocked_ipv6_cidr, &cidr_key);
    }
    if (!policy_applies(policy, port, dir)) {
        policy = bpf_map_lookup_elem(&blocked_ports, &port);
    }
    if (!policy_applies(policy, port, dir)) {
        return NULL;
    }
    return policy;
}

/* Pack an IPv4 endpoint into the ringbuf target encoding (flag byte 0x01). */
static __always_inline void pack_v4_target(char *target, __u32 ip, __u16 port) {
    __builtin_memcpy(target, &ip, 4);
    __builtin_memcpy(target + 4, &port, 2);
    target[6] = 0x01;
}

/* Pack an IPv6 endpoint into the ringbuf target encoding (flag byte 0x02). */
static __always_inline void pack_v6_target(char *target, struct ipv6_key *ip_key, __u16 port) {
    __builtin_memcpy(target, ip_key->addr, 16);
    __builtin_memcpy(target + 16, &port, 2);
    target[18] = 0x02;
}

static __always_inline __u64 hash_str(const char *str, int max_len) {
    __u64 hash = FNV_OFFSET_BASIS;
    for (int i = 0; i < 256; i++) {
        if (i >= max_len) break;
        if (str[i] == '\0') break;
        hash ^= (__u64)str[i];
        hash *= FNV_PRIME;
    }
    return hash;
}

static __always_inline int is_in_container(struct task_struct *task) {
    struct nsproxy *nsproxy = BPF_CORE_READ(task, nsproxy);
    if (!nsproxy) return 0;
    struct pid_namespace *pid_ns = BPF_CORE_READ(nsproxy, pid_ns_for_children);
    if (!pid_ns) return 0;
    unsigned int level = BPF_CORE_READ(pid_ns, level);
    return level > 0;
}

static __always_inline int enforce_policy(struct policy_val *policy, struct task_struct *task, const char *target_name, const char *hook_name) {
    if (policy->only_in_container && !is_in_container(task)) {
        return 0; // Allowed: policy only applies to containers, and this is host
    }

    bool matched = false;
    if (policy->block_unconditionally) {
        matched = true;
    } else {
        // Strict ordered ancestry chain check using stateful process tracker
        __u32 curr_pid = bpf_get_current_pid_tgid() >> 32;
        struct process_info *pinfo = bpf_map_lookup_elem(&processes, &curr_pid);
        if (pinfo) {
            matched = true;
            #pragma unroll
            for (int i = 0; i < 8; i++) {
                if (policy->ancestor_hashes[i] == 0) break; // End of configured chain
                
                bool found = false;
                if (policy->ancestor_hashes[i] == pinfo->exe_hash) {
                    found = true;
                } else {
                    #pragma unroll
                    for (int j = 0; j < 8; j++) {
                        if (policy->ancestor_hashes[i] == pinfo->ancestors[j]) {
                            found = true;
                            break;
                        }
                    }
                }
                
                if (!found) {
                    matched = false;
                    break;
                }
            }
        } else {
            matched = false; // Cannot verify ancestry
        }
    }

    // Argument filtering check
    if (matched) {
        bool has_arg_filter = false;
        for (int i = 0; i < 32; i++) {
            if (policy->blocked_arg_hashes[i] != 0) {
                has_arg_filter = true;
                break;
            }
        }
        if (has_arg_filter) {
            __u32 pid = bpf_get_current_pid_tgid() >> 32;
            struct exec_args *eargs = bpf_map_lookup_elem(&exec_args_map, &pid);
            if (eargs) {
                bool arg_matched = false;
                for (int i = 0; i < 32; i++) {
                    if (policy->blocked_arg_hashes[i] == 0) break;
                    for (int j = 0; j < 32; j++) {
                        if (eargs->arg_hashes[j] == policy->blocked_arg_hashes[i]) {
                            arg_matched = true;
                            break;
                        }
                    }
                    if (arg_matched) break;
                }
                matched = arg_matched;
            } else {
                matched = false; // If we couldn't get arguments, we can't filter
            }
        }
    }

    if (!matched) return 0;

    if (policy->action == ACTION_ALLOW) {
        return 0; // Silently allow and bypass further blocks
    }

    struct event *e = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (e) {
        e->pid = bpf_get_current_pid_tgid() >> 32;
        e->action = policy->action;
        bpf_core_read_str(e->hook, sizeof(e->hook), hook_name);

        // Network hooks pack the target as RAW BINARY (IP bytes + port + flag),
        // which can legitimately contain 0x00 bytes (e.g. 0.0.0.0, or any octet
        // that happens to be zero). bpf_core_read_str stops at the first NUL, so
        // it truncates or empties these. Copy a fixed-length blob for network
        // hooks; keep the NUL-terminated string copy for path-based hooks
        // (exec/file), whose targets are real C strings.
        //   network hook names: "connect", "bind", "listen", "accept"
        char h0 = hook_name[0];
        if (h0 == 'c' || h0 == 'b' || h0 == 'l' || h0 == 'a') {
            // 19 bytes covers the widest packed form (IPv6: 16 addr + 2 port + 1 flag).
            bpf_probe_read_kernel(e->target, 19, target_name);
        } else {
            bpf_core_read_str(e->target, sizeof(e->target), target_name);
        }
        bpf_ringbuf_submit(e, 0);
    }

    if (policy->action == ACTION_ALERT) {
        return 0;
    } else if (policy->action == ACTION_KILL) {
        bpf_send_signal(policy->kill_signal ? policy->kill_signal : 9); // Custom signal or SIGKILL
        return -EPERM;
    } else if (policy->action == ACTION_DECEIVE) {
        // Socket-family hooks lie with -ECONNREFUSED; file/exec hooks lie with -ENOENT.
        // Network hooks: "connect", "bind", "listen", "accept".
        char h0 = hook_name[0];
        if (h0 == 'c' || h0 == 'b' || h0 == 'l' || h0 == 'a')
            return -111; // -ECONNREFUSED
        return -ENOENT;
    } else { // ACTION_BLOCK
        return -EPERM;
    }
}

SEC("lsm/bprm_check_security")
int BPF_PROG(restrict_exec, struct linux_binprm *bprm, int ret) {
    if (ret != 0) return ret;

    __u32 zero = 0;
    struct path_buf *buf = bpf_map_lookup_elem(&path_buffer, &zero);
    if (!buf) return 0;
    char *filename = buf->data;
    
    // Clear the buffer
    __builtin_memset(filename, 0, 256);

    struct file *file = bprm->file;
    if (!file) return 0;

    int len = bpf_d_path(&file->f_path, filename, 256);
    if (len < 0) return 0;

    __u64 key = hash_str(filename, 256);
    struct policy_val *policy = bpf_map_lookup_elem(&blocked_binaries, &key);
    if (!policy) {
        // Fallback to LPM Trie prefix matching
        __u32 zero2 = 0;
        struct path_lpm_key *lpm_key = bpf_map_lookup_elem(&lpm_key_buffer, &zero2);
        if (lpm_key) {
            __builtin_memset(lpm_key, 0, sizeof(*lpm_key));
            lpm_key->prefixlen = 256 * 8; // Max prefix length in bits
            __builtin_memcpy(lpm_key->data, filename, 256);
            policy = bpf_map_lookup_elem(&blocked_binaries_lpm, lpm_key);
        }
    }
    if (!policy) return 0;

    struct task_struct *task = bpf_get_current_task_btf();
    int ret_val = enforce_policy(policy, task, filename, "exec");



    return ret_val;
}

SEC("lsm/bprm_committing_creds")
int BPF_PROG(commit_creds, struct linux_binprm *bprm) {
    __u32 zero = 0;
    struct path_buf *buf = bpf_map_lookup_elem(&path_buffer, &zero);
    if (!buf) return 0;
    char *filename = buf->data;
    __builtin_memset(filename, 0, 256);

    struct file *file = bprm->file;
    if (!file) return 0;
    int len = bpf_d_path(&file->f_path, filename, 256);
    if (len < 0) return 0;

    __u64 key = hash_str(filename, 256);
    __u32 curr_pid = bpf_get_current_pid_tgid() >> 32;
    struct process_info *pinfo = bpf_map_lookup_elem(&processes, &curr_pid);
    
    struct process_info *new_info = bpf_map_lookup_elem(&process_info_buffer, &zero);
    if (new_info) {
        __builtin_memset(new_info, 0, sizeof(*new_info));
        if (pinfo) {
            for (int i = 7; i > 0; i--) {
                new_info->ancestors[i] = pinfo->ancestors[i-1];
            }
            new_info->ancestors[0] = pinfo->exe_hash;
        }
        new_info->exe_hash = key;
        bpf_map_update_elem(&processes, &curr_pid, new_info, BPF_ANY);
    }
    return 0;
}

SEC("lsm/file_open")
int BPF_PROG(restrict_file, struct file *file) {
    __u32 zero = 0;
    struct path_buf *buf = bpf_map_lookup_elem(&path_buffer, &zero);
    if (!buf) return 0;
    char *filename = buf->data;
    
    // Clear the buffer
    __builtin_memset(filename, 0, 256);

    int len = bpf_d_path(&file->f_path, filename, 256);
    if (len < 0) return 0;

    __u64 key = hash_str(filename, 256);
    struct policy_val *policy = bpf_map_lookup_elem(&blocked_files, &key);
    if (!policy) {
        // Fallback to LPM Trie prefix matching
        __u32 zero2 = 0;
        struct path_lpm_key *lpm_key = bpf_map_lookup_elem(&lpm_key_buffer, &zero2);
        if (lpm_key) {
            __builtin_memset(lpm_key, 0, sizeof(*lpm_key));
            lpm_key->prefixlen = 256 * 8; // Max prefix length in bits
            __builtin_memcpy(lpm_key->data, filename, 256);
            policy = bpf_map_lookup_elem(&blocked_files_lpm, lpm_key);
        }
    }
    if (!policy) return 0;

    if (policy->action == ACTION_ALERT) {
        __u64 file_ptr = (__u64)file;
        
        __u32 zero = 0;
        struct file_stat *stat = bpf_map_lookup_elem(&stat_buffer, &zero);
        if (stat) {
            __builtin_memset(stat, 0, sizeof(*stat));
            __builtin_memcpy(stat->filename, filename, sizeof(stat->filename));
            bpf_map_update_elem(&file_stats, &file_ptr, stat, BPF_ANY);
        }
        return 0; // Allow access and begin tracking bytes
    }
    
    struct task_struct *task = bpf_get_current_task_btf();
    return enforce_policy(policy, task, filename, "file");
}

SEC("lsm/socket_connect")
int BPF_PROG(restrict_connect, struct socket *sock, struct sockaddr *address, int addrlen) {
    if (!address) return 0;
    
    short unsigned int sa_family = BPF_CORE_READ(address, sa_family);
    if (sa_family == AF_INET) {
        __u16 port = BPF_CORE_READ((struct sockaddr_in *)address, sin_port);
        port = __builtin_bswap16(port);
        __u32 ip = BPF_CORE_READ((struct sockaddr_in *)address, sin_addr.s_addr);

        struct policy_val *policy = lookup_v4_policy(ip, port, DIR_CONNECT);
        if (policy) {
            // Encode ip and port into target as raw bytes for userspace to decode.
            // Userspace formats it into human readable "A.B.C.D:PORT".
            char target[40] = {};
            pack_v4_target(target, ip, port);

            struct task_struct *task = bpf_get_current_task_btf();
            return enforce_policy(policy, task, target, "connect");
        }
    } else if (sa_family == AF_INET6) {
        __u16 port = BPF_CORE_READ((struct sockaddr_in6 *)address, sin6_port);
        port = __builtin_bswap16(port);
        struct ipv6_key ip_key = {};
        BPF_CORE_READ_INTO(&ip_key.addr, (struct sockaddr_in6 *)address, sin6_addr.in6_u.u6_addr8);

        struct policy_val *policy = lookup_v6_policy(&ip_key, port, DIR_CONNECT);
        if (policy) {
            char target[40] = {};
            pack_v6_target(target, &ip_key, port);

            struct task_struct *task = bpf_get_current_task_btf();
            return enforce_policy(policy, task, target, "connect");
        }
    }
    return 0;
}

SEC("lsm/task_alloc")
int BPF_PROG(track_task_alloc, struct task_struct *task, unsigned long clone_flags) {
    __u32 parent_pid = bpf_get_current_pid_tgid() >> 32;
    __u32 child_pid = BPF_CORE_READ(task, tgid);

    struct process_info *parent_info = bpf_map_lookup_elem(&processes, &parent_pid);
    if (parent_info) {
        bpf_map_update_elem(&processes, &child_pid, parent_info, BPF_ANY);
    }
    return 0;
}

SEC("lsm/task_free")
int BPF_PROG(track_task_free, struct task_struct *task) {
    __u32 pid = BPF_CORE_READ(task, tgid);
    bpf_map_delete_elem(&processes, &pid);
    bpf_map_delete_elem(&exec_args_map, &pid);
    return 0;
}

struct trace_event_raw_sys_enter_execve {
    unsigned long long unused;
    int __syscall_nr;
    const char *filename;
    const char *const *argv;
    const char *const *envp;
};

SEC("tracepoint/syscalls/sys_enter_execve")
int tracepoint_sys_enter_execve(struct trace_event_raw_sys_enter_execve *ctx) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct exec_args args = {};
    
    // Read up to 32 arguments
    const char *argp;
    char buf[128];
    for (int i = 0; i < 32; i++) {
        // Read the pointer to the i-th string in argv
        if (bpf_probe_read_user(&argp, sizeof(argp), &ctx->argv[i]) != 0 || !argp) {
            break;
        }
        // Read the string itself
        if (bpf_probe_read_user_str(buf, sizeof(buf), argp) > 0) {
            args.arg_hashes[i] = hash_str(buf, 128);
        }
    }
    
    bpf_map_update_elem(&exec_args_map, &pid, &args, BPF_ANY);
    return 0;
}

SEC("fexit/vfs_read")
int BPF_PROG(vfs_read_exit, struct file *file, char *buf, size_t count, loff_t *pos, ssize_t ret) {
    if (ret <= 0) return 0;
    __u64 file_ptr = (__u64)file;
    struct file_stat *stat = bpf_map_lookup_elem(&file_stats, &file_ptr);
    if (stat) {
        __sync_fetch_and_add(&stat->bytes_read, ret);
    }
    return 0;
}

SEC("fexit/vfs_write")
int BPF_PROG(vfs_write_exit, struct file *file, const char *buf, size_t count, loff_t *pos, ssize_t ret) {
    if (ret <= 0) return 0;
    __u64 file_ptr = (__u64)file;
    struct file_stat *stat = bpf_map_lookup_elem(&file_stats, &file_ptr);
    if (stat) {
        __sync_fetch_and_add(&stat->bytes_written, ret);
    }
    return 0;
}

SEC("lsm/file_free_security")
int BPF_PROG(track_file_free, struct file *file) {
    __u64 file_ptr = (__u64)file;
    struct file_stat *stat = bpf_map_lookup_elem(&file_stats, &file_ptr);
    if (stat) {
        struct event *e = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
        if (e) {
            e->pid = bpf_get_current_pid_tgid() >> 32;
            e->action = ACTION_ALERT;
            __builtin_memcpy(e->hook, "file_io_summary\0", 16);
            
            __builtin_memcpy(e->target, &stat->bytes_read, 8);
            __builtin_memcpy(e->target + 8, &stat->bytes_written, 8);
            e->target[16] = 0x03; // Flag

            __builtin_memcpy(e->target + 17, stat->filename, 128);
            
            bpf_ringbuf_submit(e, 0);
        }
        bpf_map_delete_elem(&file_stats, &file_ptr);
    }
    return 0;
}

/* =====================================================================
 * INBOUND / SERVER-SIDE ENFORCEMENT
 *
 * restrict_connect() above covers egress initiation only (our processes
 * dialing out). The hooks below cover the server side of the connection:
 *
 *   socket_bind   - what local address:port a process may listen on
 *   socket_listen - which listening sockets may enter the LISTEN state
 *   socket_accept - which remote peers may be accepted (and therefore
 *                   which peers our responses are ever sent to)
 *
 * socket_accept is the real "outgoing response" control point: denying it
 * refuses the accept, so no response is ever emitted to a blocked peer.
 *
 * All three reuse policy_val, enforce_policy(), and the existing network
 * blocklist maps. No new maps are introduced.
 * ===================================================================== */

/*
 * socket_bind: `address` is the local address the process is binding to.
 * Enforced against the same network maps, so a rule on port 4444 prevents
 * a reverse shell from *listening* on 4444, not just dialing out to it.
 */
SEC("lsm/socket_bind")
int BPF_PROG(restrict_bind, struct socket *sock, struct sockaddr *address, int addrlen) {
    if (!address) return 0;

    short unsigned int sa_family = BPF_CORE_READ(address, sa_family);

    if (sa_family == AF_INET) {
        __u16 port = BPF_CORE_READ((struct sockaddr_in *)address, sin_port);
        port = __builtin_bswap16(port);
        __u32 ip = BPF_CORE_READ((struct sockaddr_in *)address, sin_addr.s_addr);

        struct policy_val *policy = lookup_v4_policy(ip, port, DIR_BIND);
        if (policy) {
            char target[40] = {};
            pack_v4_target(target, ip, port);
            struct task_struct *task = bpf_get_current_task_btf();
            return enforce_policy(policy, task, target, "bind");
        }
    } else if (sa_family == AF_INET6) {
        __u16 port = BPF_CORE_READ((struct sockaddr_in6 *)address, sin6_port);
        port = __builtin_bswap16(port);

        struct ipv6_key ip_key = {};
        BPF_CORE_READ_INTO(&ip_key.addr, (struct sockaddr_in6 *)address, sin6_addr.in6_u.u6_addr8);

        struct policy_val *policy = lookup_v6_policy(&ip_key, port, DIR_BIND);
        if (policy) {
            char target[40] = {};
            pack_v6_target(target, &ip_key, port);
            struct task_struct *task = bpf_get_current_task_btf();
            return enforce_policy(policy, task, target, "bind");
        }
    }
    return 0;
}

/*
 * socket_listen: no sockaddr is passed. The bound local address lives on
 * sock->sk. skc_num is the local port in host byte order already;
 * skc_rcv_saddr is the bound local address.
 */
SEC("lsm/socket_listen")
int BPF_PROG(restrict_listen, struct socket *sock, int backlog) {
    struct sock *sk = BPF_CORE_READ(sock, sk);
    if (!sk) return 0;

    short unsigned int family = BPF_CORE_READ(sk, __sk_common.skc_family);
    __u16 port = BPF_CORE_READ(sk, __sk_common.skc_num); // host byte order

    if (family == AF_INET) {
        __u32 ip = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);

        struct policy_val *policy = lookup_v4_policy(ip, port, DIR_LISTEN);
        if (policy) {
            char target[40] = {};
            pack_v4_target(target, ip, port);
            struct task_struct *task = bpf_get_current_task_btf();
            return enforce_policy(policy, task, target, "listen");
        }
    } else if (family == AF_INET6) {
        struct ipv6_key ip_key = {};
        BPF_CORE_READ_INTO(&ip_key.addr, sk, __sk_common.skc_v6_rcv_saddr.in6_u.u6_addr8);

        struct policy_val *policy = lookup_v6_policy(&ip_key, port, DIR_LISTEN);
        if (policy) {
            char target[40] = {};
            pack_v6_target(target, &ip_key, port);
            struct task_struct *task = bpf_get_current_task_btf();
            return enforce_policy(policy, task, target, "listen");
        }
    }
    return 0;
}

/*
 * socket_accept: `newsock` is the freshly-created socket for the incoming
 * peer. The peer address is on newsock->sk (skc_daddr / skc_dport).
 *
 * NOTE: skc_dport is stored in network byte order; skc_num is host order.
 * We evaluate against the *peer* (remote) address, since that is the entity
 * our responses would flow to. Returning non-zero here refuses the accept.
 *
 * At the time socket_accept fires, newsock->sk may not yet be populated on
 * all kernels/protocols. We fall back to the listening socket's local port
 * so that a port-only rule still applies.
 */
SEC("lsm/socket_accept")
int BPF_PROG(restrict_accept, struct socket *sock, struct socket *newsock) {
    if (!newsock) return 0;

    struct sock *newsk = BPF_CORE_READ(newsock, sk);
    if (!newsk) {
        // At lsm/socket_accept time the kernel has allocated newsock but has
        // NOT yet populated newsock->sk with the peer — that happens later,
        // inside inet_accept(). So the remote peer IP is genuinely unavailable
        // here. We enforce on, and report, the LISTENING socket's local
        // address:port instead (which IS available via sock->sk). This still
        // gives a useful, non-empty target like "0.0.0.0:8080" telling you
        // *which service* accepted a connection.
        struct sock *lsk = BPF_CORE_READ(sock, sk);
        if (!lsk) return 0;

        __u16 lport = BPF_CORE_READ(lsk, __sk_common.skc_num);
        struct policy_val *policy = bpf_map_lookup_elem(&blocked_ports, &lport);
        if (!policy_applies(policy, lport, DIR_ACCEPT)) return 0;

        __u32 local_ip = BPF_CORE_READ(lsk, __sk_common.skc_rcv_saddr);
        char target[40] = {};
        pack_v4_target(target, local_ip, lport);
        struct task_struct *task = bpf_get_current_task_btf();
        return enforce_policy(policy, task, target, "accept");
    }

    short unsigned int family = BPF_CORE_READ(newsk, __sk_common.skc_family);
    __u16 peer_port = BPF_CORE_READ(newsk, __sk_common.skc_dport);
    peer_port = __builtin_bswap16(peer_port); // network -> host order

    if (family == AF_INET) {
        __u32 peer_ip = BPF_CORE_READ(newsk, __sk_common.skc_daddr);

        // Match the peer IP against IP/CIDR rules. Port rules for accept are
        // matched against the *local* service port, not the peer's ephemeral port.
        __u16 local_port = BPF_CORE_READ(newsk, __sk_common.skc_num);

        struct policy_val *policy = lookup_v4_policy(peer_ip, local_port, DIR_ACCEPT);
        if (!policy) {
            // Peer's own source port may itself be blocklisted (e.g. known C2 source ports)
            policy = lookup_v4_policy(peer_ip, peer_port, DIR_ACCEPT);
        }
        if (policy) {
            char target[40] = {};
            pack_v4_target(target, peer_ip, peer_port);
            struct task_struct *task = bpf_get_current_task_btf();
            return enforce_policy(policy, task, target, "accept");
        }
    } else if (family == AF_INET6) {
        struct ipv6_key ip_key = {};
        BPF_CORE_READ_INTO(&ip_key.addr, newsk, __sk_common.skc_v6_daddr.in6_u.u6_addr8);

        __u16 local_port = BPF_CORE_READ(newsk, __sk_common.skc_num);

        struct policy_val *policy = lookup_v6_policy(&ip_key, local_port, DIR_ACCEPT);
        if (!policy) {
            policy = lookup_v6_policy(&ip_key, peer_port, DIR_ACCEPT);
        }
        if (policy) {
            char target[40] = {};
            pack_v6_target(target, &ip_key, peer_port);
            struct task_struct *task = bpf_get_current_task_btf();
            return enforce_policy(policy, task, target, "accept");
        }
    }
    return 0;
}