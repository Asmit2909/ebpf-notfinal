// xdp_waf.c — Path A: L3/L4 filter; legit traffic goes up the kernel stack.
// Build is handled by the Makefile (clang -O2 -g -target bpf).
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/if_link.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// IPv4 blocklist (LPM so you can block single IPs and subnets).
struct ipv4_lpm_key { __u32 prefixlen; __u32 addr; };
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 100000);
    __type(key, struct ipv4_lpm_key);
    __type(value, __u8);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} blocklist_v4 SEC(".maps");

// IPv4 allowlist (LPM, same shape as blocklist_v4). Entries here bypass
// the blocklist and rate limiter entirely — use for trusted sources
// (health checks, internal monitoring, known partners).
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 100000);
    __type(key, struct ipv4_lpm_key);
    __type(value, __u8);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} allowlist_v4 SEC(".maps");

// Per-source-IP token bucket for crude SYN-flood / rate limiting.
struct rl_val { __u64 last_ns; __u64 tokens; };
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1000000);
    __type(key, __u32);          // src IPv4
    __type(value, struct rl_val);
} ratelimit_v4 SEC(".maps");

// Optional TCP destination-port allowlist. Empty/unset sentinel = allow all.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 64);
    __type(key, __u16);          // dport, network order
    __type(value, __u8);
} tcp_port_allow SEC(".maps");

// Counters for observability (per-CPU; summed in userspace).
enum { C_PASS, C_DROP_MALFORMED, C_DROP_BLOCK, C_DROP_RATE, C_DROP_PORT, C_SYN_SEEN, C_MAX };
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, C_MAX);
    __type(key, __u32);
    __type(value, __u64);
} stats SEC(".maps");

// Latency histogram: 64 log2-ns buckets covering ~1 ns to ~9 seconds.
// Bucket i holds packets whose XDP program latency satisfied:
//   2^i ns <= latency < 2^(i+1) ns
// All measurement is pure eBPF bookkeeping; no filtering logic is changed.
#define LAT_BUCKETS 64
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, LAT_BUCKETS);
    __type(key, __u32);
    __type(value, __u64);
} latency_hist SEC(".maps");

// === PATH B ===
// Uncomment to add the AF_XDP redirect map when extending:
// #define MAX_QUEUES 64
// struct {
//     __uint(type, BPF_MAP_TYPE_XSKMAP);
//     __uint(max_entries, MAX_QUEUES);
//     __type(key, __u32);
//     __type(value, __u32);
// } xsks_map SEC(".maps");

#define RL_RATE_PER_SEC   2000ULL
#define RL_BURST          4000ULL
#define NS_PER_SEC        1000000000ULL

static __always_inline void bump(__u32 idx) {
    __u64 *c = bpf_map_lookup_elem(&stats, &idx);
    if (c) (*c)++;
}

// Record one latency sample (nanoseconds) into the log2 histogram.
static __always_inline void record_latency(__u64 ns) {
    __u32 bucket = 0;
    // Manual log2: the verifier needs a bounded loop, so we unroll via
    // a simple shift-until-zero approach capped at LAT_BUCKETS-1.
    __u64 v = ns;
    if (v) {
        // clz on 64-bit: bucket = 63 - __builtin_clzll(v)
        bucket = 63 - ((__u32)__builtin_clzll(v));
        if (bucket >= LAT_BUCKETS) bucket = LAT_BUCKETS - 1;
    }
    __u64 *c = bpf_map_lookup_elem(&latency_hist, &bucket);
    if (c) (*c)++;
}

// Validate iph->tot_len against the actual captured packet length.
// Returns 1 if consistent (safe to trust tot_len for any future payload
// math), 0 if the declared total length is impossible given data_end,
// or smaller than the IP header itself.
static __always_inline int ipv4_total_len_ok(struct iphdr *iph,
                                              void *data, void *data_end) {
    __u16 tot_len = bpf_ntohs(iph->tot_len);

    // tot_len must at least cover the IP header itself.
    __u32 ihl_bytes = iph->ihl * 4;
    if (tot_len < ihl_bytes) return 0;

    // The packet (from the start of the IP header) must not claim to be
    // longer than what's actually in the buffer.
    __u32 captured_ip_bytes = (__u32)(data_end - (void *)iph);
    if (tot_len > captured_ip_bytes) return 0;

    return 1;
}

static __always_inline int rate_limit_ok(__u32 saddr) {
    __u64 now = bpf_ktime_get_ns();
    struct rl_val *v = bpf_map_lookup_elem(&ratelimit_v4, &saddr);
    if (!v) {
        struct rl_val init = { .last_ns = now, .tokens = RL_BURST - 1 };
        bpf_map_update_elem(&ratelimit_v4, &saddr, &init, BPF_ANY);
        return 1;
    }
    __u64 elapsed = now - v->last_ns;
    __u64 refill  = (elapsed * RL_RATE_PER_SEC) / NS_PER_SEC;
    __u64 tokens  = v->tokens + refill;
    if (tokens > RL_BURST) tokens = RL_BURST;
    v->last_ns = now;
    if (tokens == 0) { v->tokens = 0; return 0; }
    v->tokens = tokens - 1;
    return 1;
}

// Latency-aware return: record elapsed ns, then return the XDP verdict.
// Used in place of bare return statements so every exit path is measured.
#define WAF_RETURN(verdict) do {                                \
    record_latency(bpf_ktime_get_ns() - t_start);              \
    return (verdict);                                           \
} while (0)

SEC("xdp")
int xdp_waf_prog(struct xdp_md *ctx) {
    __u64 t_start = bpf_ktime_get_ns();   // latency: start

    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) { bump(C_DROP_MALFORMED); WAF_RETURN(XDP_DROP); }

    __u16 h_proto = eth->h_proto;

    if (h_proto == bpf_htons(ETH_P_IP)) {
        struct iphdr *iph = (void *)(eth + 1);
        if ((void *)(iph + 1) > data_end) { bump(C_DROP_MALFORMED); WAF_RETURN(XDP_DROP); }
        if (iph->ihl < 5)                 { bump(C_DROP_MALFORMED); WAF_RETURN(XDP_DROP); }
        
        if (!ipv4_total_len_ok(iph, data, data_end)) { bump(C_DROP_MALFORMED); WAF_RETURN(XDP_DROP); }

        __u32 saddr = iph->saddr;

        // 0) Allowlist short-circuits blocklist + rate limit (but still goes
        //    through the port-allow check below, so it can't bypass policy
        //    entirely — just floods/blocks).
        struct ipv4_lpm_key k = { .prefixlen = 32, .addr = saddr };
        int is_allowed = bpf_map_lookup_elem(&allowlist_v4, &k) != NULL;

        if (!is_allowed) {
            // 1) Blocklist (subnet-aware).
            if (bpf_map_lookup_elem(&blocklist_v4, &k)) { bump(C_DROP_BLOCK); WAF_RETURN(XDP_DROP); }

            // 2) Rate limit (sheds floods before they cost nginx/transformer CPU).
            if (!rate_limit_ok(saddr)) { bump(C_DROP_RATE); WAF_RETURN(XDP_DROP); }
        }

        // 3) Optional port allowlist for TCP.
        if (iph->protocol == IPPROTO_TCP) {
            struct tcphdr *tcp = (void *)iph + iph->ihl * 4;
            if ((void *)(tcp + 1) > data_end) { bump(C_DROP_MALFORMED); WAF_RETURN(XDP_DROP); }

            // SYN-flood observability: count SYN-only packets (new connection attempts).
            if (tcp->syn && !tcp->ack) {
                bump(C_SYN_SEEN);
            }

            __u16 dport = tcp->dest;
            __u8 *allowed = bpf_map_lookup_elem(&tcp_port_allow, &dport);
            __u16 sentinel = 0;
            __u8 *active = bpf_map_lookup_elem(&tcp_port_allow, &sentinel);
            if (active && !allowed) { bump(C_DROP_PORT); WAF_RETURN(XDP_DROP); }

            // === PATH B ===
            // Replace the XDP_PASS below with AF_XDP redirect:
            //   __u32 idx = ctx->rx_queue_index;
            //   if (bpf_map_lookup_elem(&xsks_map, &idx))
            //       return bpf_redirect_map(&xsks_map, idx, 0);
        }

        bump(C_PASS);
        WAF_RETURN(XDP_PASS);   // up the kernel stack -> nginx -> transformer
    }

    // IPv6, ARP, everything else must reach the kernel or you break the box.
    bump(C_PASS);
    WAF_RETURN(XDP_PASS);
}

char _license[] SEC("license") = "GPL";