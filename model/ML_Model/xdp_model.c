#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include "src/model_weights.h"

#ifndef bpf_htons
#define bpf_htons(x) __builtin_bswap16(x)
#endif
#ifndef bpf_ntohs
#define bpf_ntohs(x) __builtin_bswap16(x)
#endif
#ifndef bpf_htonl
#define bpf_htonl(x) __builtin_bswap32(x)
#endif
#ifndef bpf_ntohl
#define bpf_ntohl(x) __builtin_bswap32(x)
#endif

// ═══════════════════════════════════════════════════════
// Tunable Thresholds
// ═══════════════════════════════════════════════════════
#define GLOBAL_PKT_RATE_THRESHOLD   500
#define GLOBAL_SRC_DIVERSITY_THRESH 1
#define WINDOW_DURATION_US          1000000
#define WHITELIST_TTL_US            300000000 // 5 minutes

// SYN Cookie Secrets
#define SYN_COOKIE_SECRET   0xDEADBEEF42C0FFEEull
#define COOKIE_TIME_SHIFT   26

// struct bpf_map_def {
//     unsigned int type;
//     unsigned int key_size;
//     unsigned int value_size;
//     unsigned int max_entries;
//     unsigned int map_flags;
// };

// ═══════════════════════════════════════════════════════
// BPF Maps
// ═══════════════════════════════════════════════════════
struct flow_state {
    __u64 start_time;
    __u64 last_time;
    __u64 count;
    __u64 sum_len;
    __u64 sum_sq_len;
    __u64 sum_iat;
    __u64 sum_sq_iat;
    __u64 max_iat;
    __u16 dest_port;
    __u16 init_win_bytes;
};



struct dst_key {
    __u32 dst_ip;
    __u16 dst_port;
    __u16 pad;
};

struct dst_state {
    __u64 window_start;
    __u64 pkt_count;
    __u64 src_bitmap[4];
    __u64 is_under_attack;
    __u64 was_under_attack;
};

struct whitelist_entry {
    __u64 expires_at;
};


struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);
    __type(value, struct flow_state);
} flow_tracking SEC(".maps");

/* 
 * Map 2: global_dst_tracking
 * Tracks aggregate traffic hitting a specific (dst_ip, dst_port).
 * Uses a 256-bit bloom filter to estimate source IP diversity.
 */
 struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, struct dst_key);
    __type(value, struct dst_state);
} global_dst_tracking SEC(".maps");



/* 
 * Map 3: whitelist
 * Stores verified source IPs (those who solved the SYN cookie
 * or were classified as Benign by the ML model).
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u32);
    __type(value, struct whitelist_entry);
} whitelist SEC(".maps");

// ═══════════════════════════════════════════════════════
// Helper Functions
// ═══════════════════════════════════════════════════════
static __always_inline long long get_sign_mask(long long val) {
    long long mask = val;
    asm volatile ("%0 s>>= 63" : "+r"(mask));
    return mask;
}

static __always_inline unsigned long long fast_isqrt(unsigned long long n) {
    unsigned long long root = 0;
    unsigned long long bit = 1ULL << 38;
    #pragma clang loop unroll(full)
    for(int i = 0; i < 20; i++) {
        unsigned long long trial = root + bit;
        long long diff = (long long)n - (long long)trial;
        unsigned long long cond = get_sign_mask(diff) + 1;
        n -= trial * cond;
        root = (root >> 1) + (bit * cond);
        bit >>= 2;
    }
    return root;
}

static __always_inline __u64 popcount64(__u64 x) {
    x = x - ((x >> 1) & 0x5555555555555555ULL);
    x = (x & 0x3333333333333333ULL) + ((x >> 2) & 0x3333333333333333ULL);
    x = (x + (x >> 4)) & 0x0F0F0F0F0F0F0F0FULL;
    return (x * 0x0101010101010101ULL) >> 56;
}

// ═══════════════════════════════════════════════════════
// Layer 1: Global DDoS Detector
// ═══════════════════════════════════════════════════════
static __always_inline int check_global_ddos(__u32 dst_ip, __u16 dst_port, __u32 src_ip, __u64 now) {
    struct dst_key key = { .dst_ip = dst_ip, .dst_port = dst_port, .pad = 0 };
    struct dst_state *state = bpf_map_lookup_elem(&global_dst_tracking, &key);
    
    if (!state) {
        struct dst_state new_state = {0};
        new_state.window_start = now;
        new_state.pkt_count = 1;
        __u32 hash = src_ip * 2654435761U;
        __u32 bit_index = (hash >> 24);
        new_state.src_bitmap[bit_index / 64] |= (1ULL << (bit_index % 64));
        bpf_map_update_elem(&global_dst_tracking, &key, &new_state, BPF_ANY);
        return 0;
    }

    if (now - state->window_start > WINDOW_DURATION_US) {
        state->window_start = now;
        state->was_under_attack = state->is_under_attack;
        state->pkt_count = 1;
        state->is_under_attack = 0;
        state->src_bitmap[0] = 0; state->src_bitmap[1] = 0;
        state->src_bitmap[2] = 0; state->src_bitmap[3] = 0;
        __u32 hash = src_ip * 2654435761U;
        __u32 bit_index = (hash >> 24);
        state->src_bitmap[bit_index / 64] |= (1ULL << (bit_index % 64));
        return state->was_under_attack;
    }

    state->pkt_count += 1;
    __u32 hash = src_ip * 2654435761U;
    __u32 bit_index = (hash >> 24);
    state->src_bitmap[bit_index / 64] |= (1ULL << (bit_index % 64));

    __u64 unique_sources = popcount64(state->src_bitmap[0]) + popcount64(state->src_bitmap[1]) +
                           popcount64(state->src_bitmap[2]) + popcount64(state->src_bitmap[3]);

    if (state->pkt_count > GLOBAL_PKT_RATE_THRESHOLD && unique_sources > GLOBAL_SRC_DIVERSITY_THRESH) {
        if (!state->is_under_attack && (state->pkt_count < GLOBAL_PKT_RATE_THRESHOLD + 10 || state->pkt_count % 1000 == 0)) {
            bpf_printk("DISTRIBUTED DDoS! Alarm ON (%llu pkts)\n", state->pkt_count);
        }
        state->is_under_attack = 1;
        return 1;
    }

    if (state->was_under_attack) {
        if (state->pkt_count > (GLOBAL_PKT_RATE_THRESHOLD / 5)) {
            state->is_under_attack = 1;
        }
    }
    return state->is_under_attack || state->was_under_attack;
}

// ═══════════════════════════════════════════════════════
// SYN Cookie Implementation
// ═══════════════════════════════════════════════════════
static __always_inline __u32 generate_syn_cookie(__u32 src_ip, __u16 src_port, __u32 dst_ip, __u16 dst_port, __u64 now_us) {
    __u64 time_window = now_us >> COOKIE_TIME_SHIFT;
    __u64 hash = 14695981039346656037ULL; 
    
    hash ^= src_ip; hash *= 1099511628211ULL;
    hash ^= dst_ip; hash *= 1099511628211ULL;
    __u32 ports = ((__u32)src_port << 16) | dst_port;
    hash ^= ports; hash *= 1099511628211ULL;
    hash ^= SYN_COOKIE_SECRET; hash *= 1099511628211ULL;
    hash ^= time_window; hash *= 1099511628211ULL;
    
    return (__u32)(hash & 0xFFFFFFFF);
}

static __always_inline int verify_syn_cookie(__u32 src_ip, __u16 src_port, __u32 dst_ip, __u16 dst_port, __u32 ack_seq, __u64 now_us) {
    __u32 expected_cookie = generate_syn_cookie(src_ip, src_port, dst_ip, dst_port, now_us);
    if (ack_seq - 1 == expected_cookie) return 1;
    
    __u64 prev_us = now_us - (1ULL << COOKIE_TIME_SHIFT);
    expected_cookie = generate_syn_cookie(src_ip, src_port, dst_ip, dst_port, prev_us);
    if (ack_seq - 1 == expected_cookie) return 1;
    
    return 0;
}

static __always_inline __u16 csum_fold_helper(__u32 csum) {
    csum = (csum & 0xffff) + (csum >> 16);
    csum = (csum & 0xffff) + (csum >> 16);
    return (__u16)~csum;
}

static __always_inline int send_syn_cookie(struct xdp_md *ctx, struct ethhdr *eth, struct iphdr *ip, struct tcphdr *tcp, __u64 now_us) {
    __u32 cookie = generate_syn_cookie(ip->saddr, tcp->source, ip->daddr, tcp->dest, now_us);
    
    // Swap MAC
    for (int i = 0; i < ETH_ALEN; i++) {
        __u8 tmp = eth->h_source[i];
        eth->h_source[i] = eth->h_dest[i];
        eth->h_dest[i] = tmp;
    }
    
    // Swap IP
    __u32 tmp_ip = ip->saddr;
    ip->saddr = ip->daddr;
    ip->daddr = tmp_ip;
    
    // Swap Ports
    __u16 tmp_port = tcp->source;
    tcp->source = tcp->dest;
    tcp->dest = tmp_port;
    
    // Modify TCP Header (SYN-ACK)
    __u32 old_seq = tcp->seq;
    tcp->seq = bpf_htonl(cookie);
    tcp->ack_seq = bpf_htonl(bpf_ntohl(old_seq) + 1);
    
    __u8 *tcp_flags = (__u8 *)tcp + 13;
    *tcp_flags = 0x12; // SYN + ACK
    
    // Logically truncate packet to 40 bytes to strip options
    ip->ihl = 5;
    ip->tot_len = bpf_htons(40);
    __u8 *tcp_offset = (__u8 *)tcp + 12;
    *tcp_offset = (*tcp_offset & 0x0F) | 0x50; // doff = 5 (20 bytes)
    tcp->window = bpf_htons(8192);
    
    // IP Checksum
    ip->check = 0;
    __u32 ip_csum = 0;
    __u16 *ip_ptr = (__u16 *)ip;
    #pragma clang loop unroll(full)
    for (int i = 0; i < 10; i++) {
        ip_csum += ip_ptr[i];
    }
    ip->check = csum_fold_helper(ip_csum);
    
    // TCP Checksum
    tcp->check = 0;
    __u32 tcp_csum = 0;
    tcp_csum += (ip->saddr >> 16) & 0xFFFF;
    tcp_csum += (ip->saddr) & 0xFFFF;
    tcp_csum += (ip->daddr >> 16) & 0xFFFF;
    tcp_csum += (ip->daddr) & 0xFFFF;
    tcp_csum += bpf_htons(IPPROTO_TCP);
    tcp_csum += bpf_htons(20);
    
    __u16 *tcp_ptr = (__u16 *)tcp;
    #pragma clang loop unroll(full)
    for (int i = 0; i < 10; i++) {
        tcp_csum += tcp_ptr[i];
    }
    tcp->check = csum_fold_helper(tcp_csum);
    
    // Rate limit the printk to avoid flooding kernel logs during attack
    static __u64 challenge_count = 0;
    challenge_count++;
    if (challenge_count % 50000 == 0) {
        bpf_printk("SYN_COOKIE: Sent challenge to unverified IP (x50000)\n");
    }
    
    return XDP_TX;
}

// ═══════════════════════════════════════════════════════
// Layer 3: ML Inference Engine
// ═══════════════════════════════════════════════════════
static __always_inline int run_inference(long long raw_features[8]) {
    long long scaled_features[8];
    long long output_sum = output_bias;
    
    #pragma clang loop unroll(full)
    for (int i = 0; i < 8; i++) {
        long long raw_scaled = raw_features[i] * SCALE_FACTOR;
        long long diff = raw_scaled - scaler_mean[i];
        long long inv_std = ((long long)SCALE_FACTOR << 24) / (scaler_std[i] == 0 ? 1 : scaler_std[i]);
        scaled_features[i] = (diff * inv_std) >> 24;
    }
    
    #pragma clang loop unroll(full)
    for (int i = 0; i < 16; i++) {
        long long h_sum = hidden_bias[i];
        #pragma clang loop unroll(full)
        for (int j = 0; j < 8; j++) {
            h_sum += (scaled_features[j] * hidden_weights[i][j]) >> 10;
        }
        long long mask = get_sign_mask(h_sum);
        h_sum &= ~mask;
        output_sum += (h_sum * output_weights[i]) >> 10;
    }
    
    if (output_sum > 123) {
        // We still return the score, but we could cap it. Returning the exact score is best!
    }
    return output_sum;
}

// ═══════════════════════════════════════════════════════
// Main XDP Entry Point
// ═══════════════════════════════════════════════════════
SEC("xdp")
int xdp_ml_filter(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP)) return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) return XDP_PASS;
    if (ip->protocol != IPPROTO_TCP) return XDP_PASS;
    if (ip->ihl != 5) return XDP_PASS; // Safely ignore IP options for cookie crafting

    struct tcphdr *tcp = (void *)ip + (ip->ihl * 4);
    if ((void *)(tcp + 1) > data_end) return XDP_PASS;

    __u8 *tcp_flags = (__u8 *)tcp + 13;
    if ((void *)(tcp_flags + 1) > data_end) return XDP_PASS;
    __u8 flags = *tcp_flags;
    int is_established = (flags & 0x10) || (flags & 0x08);

    __u32 src_ip = ip->saddr;
    __u16 dst_port = bpf_ntohs(tcp->dest);
    __u16 window = bpf_ntohs(tcp->window);
    __u32 pkt_len = bpf_ntohs(ip->tot_len);
    __u64 now = bpf_ktime_get_ns() / 1000;

    int global_attack = check_global_ddos(ip->daddr, dst_port, src_ip, now);

    struct flow_state *state = bpf_map_lookup_elem(&flow_tracking, &src_ip);
    if (!state) {
        struct flow_state new_state = {0};
        new_state.start_time = now;
        new_state.last_time = now;
        new_state.count = 1;
        new_state.sum_len = pkt_len;
        new_state.sum_sq_len = (__u64)pkt_len * pkt_len;
        new_state.dest_port = dst_port;
        new_state.init_win_bytes = window;
        bpf_map_update_elem(&flow_tracking, &src_ip, &new_state, BPF_ANY);
        
        // During global attack, handle new connections via SYN Cookies!
        if (global_attack) {
            int is_syn = (flags & 0x02) && !(flags & 0x10);
            if (is_syn) {
                return send_syn_cookie(ctx, eth, ip, tcp, now);
            }
            return XDP_DROP;
        }
        return XDP_PASS;
    }

    __u64 iat = now - state->last_time;
    state->last_time = now;
    state->count += 1;
    state->sum_len += pkt_len;
    state->sum_sq_len += (__u64)pkt_len * pkt_len;
    state->sum_iat += iat;
    state->sum_sq_iat += iat * iat;
    if (iat > state->max_iat) state->max_iat = iat;

    // Layer 2: Whitelist & SYN Cookie Check
    if (global_attack) {
        struct whitelist_entry *wl = bpf_map_lookup_elem(&whitelist, &src_ip);
        if (wl && wl->expires_at > now) {
            // Whitelisted! Let them fall through to ML Layer.
        } else {
            int is_syn = (flags & 0x02) && !(flags & 0x10);
            int is_ack = (flags & 0x10);
            
            if (is_syn) {
                if (state->count > 5) {
                    // PENALTY BOX: Failed challenge 5 times.
                    if (state->count % 10000 == 0) {
                        bpf_printk("PENALTY BOX: Bot dropped (x10000)\n");
                    }
                    return XDP_DROP;
                }
                return send_syn_cookie(ctx, eth, ip, tcp, now);
            } else if (is_ack) {
                __u32 ack_seq = bpf_ntohl(tcp->ack_seq);
                if (verify_syn_cookie(src_ip, tcp->source, ip->daddr, tcp->dest, ack_seq, now)) {
                    bpf_printk("SYN_COOKIE: Verified valid user!\n");
                    struct whitelist_entry new_wl = { .expires_at = now + WHITELIST_TTL_US };
                    bpf_map_update_elem(&whitelist, &src_ip, &new_wl, BPF_ANY);
                    return XDP_DROP; // Drop this ACK so client sends data, gets RST, and retries seamlessly!
                }
            }
            if (state->count % 10000 == 0) bpf_printk("GLOBAL DDoS: Blocked unverified IP\n");
            return XDP_DROP;
        }
    }

    // Layer 3: ML Inference
    if (state->count < 5) return XDP_PASS;

    __u64 count = state->count == 0 ? 1 : state->count;
    __u64 count_minus_1 = count - 1 == 0 ? 1 : count - 1;

    long long features[8];
    features[0] = state->dest_port;
    features[1] = state->sum_len / count;
    __u64 var_len = (state->sum_sq_len / count) - (features[1] * features[1]);
    features[2] = fast_isqrt(var_len);
    features[3] = state->sum_iat / count_minus_1;
    __u64 var_iat = (state->sum_sq_iat / count_minus_1) - (features[3] * features[3]);
    features[4] = fast_isqrt(var_iat);
    features[5] = state->max_iat;
    features[6] = now - state->start_time;
    features[7] = state->init_win_bytes;

    int model_score = run_inference(features);
    
    if (state->count == 5 || state->count == 6) {
        bpf_printk("ML Model Score: %d (needs > 123 to block)\n", model_score);
    }
    
    if (model_score > 123) {
        if (state->count % 10000 == 0 || state->count < 10) {
            bpf_printk("DDoS DETECTED! Score: %d, Dropped %llu pkts\n", model_score, state->count);
        }
        return XDP_DROP;
    }

    if (is_established) {
        struct whitelist_entry new_wl = { .expires_at = now + WHITELIST_TTL_US };
        bpf_map_update_elem(&whitelist, &src_ip, &new_wl, BPF_ANY);
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
