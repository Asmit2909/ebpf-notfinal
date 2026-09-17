// waf_loader.c — libbpf userspace loader for the Path A XDP WAF.
//
// Responsibilities:
//   * load xdp_waf.o and attach to an interface (native XDP, fall back to generic)
//   * pin maps under /sys/fs/bpf/waf so they survive after this process exits
//   * load an IPv4 blocklist from a text file (CIDR or single IP per line)
//   * print per-CPU stats (summed) on demand or in a loop
//   * detach cleanly on Ctrl-C
//
// Path B hook points are marked with:  // === PATH B ===
// When you extend, the xsks_map handle and AF_XDP setup go in those spots.
//
// Build: see Makefile (needs libbpf-dev, clang). Run: sudo ./waf_loader ...

#include <argp.h>
#include <arpa/inet.h>
#include <errno.h>
#include <net/if.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <linux/if_link.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

// Must match the enum in xdp_waf.c exactly.
enum {
    C_PASS = 0,
    C_DROP_MALFORMED,
    C_DROP_BLOCK,
    C_DROP_RATE,
    C_DROP_PORT,
    C_SYN_SEEN,
    C_MAX
};
static const char *stat_names[C_MAX] = {
    "PASS", "DROP_MALFORMED", "DROP_BLOCK", "DROP_RATE", "DROP_PORT", "SYN_SEEN"
};

// LPM key must match `struct ipv4_lpm_key` in the eBPF program.
struct ipv4_lpm_key {
    __u32 prefixlen;
    __u32 addr;       // network byte order
};

#define PIN_BASEDIR "/sys/fs/bpf/waf"

static volatile sig_atomic_t exiting = 0;
static void on_sigint(int sig) { (void)sig; exiting = 1; }

// ---- CLI args ---------------------------------------------------------------

static struct env {
    const char *ifname;
    const char *obj_path;
    const char *blocklist_path;
    const char *allowlist_path;
    int generic;        // force generic (SKB) mode
    int stats_loop;     // keep printing stats until Ctrl-C
} env = {
    .obj_path = "xdp_waf.o",
};

const char *argp_program_version = "waf_loader 0.1 (Path A)";
static char doc[] =
    "XDP WAF loader (Path A).\n\n"
    "Loads the XDP filter, pins maps, optionally loads a blocklist, "
    "and reports drop/pass stats.";
static struct argp_option opts[] = {
    { "iface",     'i', "IFACE", 0, "Interface to attach to (required)" },
    { "obj",       'o', "PATH",  0, "Path to xdp_waf.o (default: ./xdp_waf.o)" },
    { "blocklist", 'b', "FILE",  0, "Load IPv4 blocklist (one IP or CIDR per line)" },
    { "allowlist", 'a', "FILE",  0, "Load IPv4 allowlist (one IP or CIDR per line)" },
    { "generic",   'g', NULL,    0, "Force generic/SKB mode (any driver)" },
    { "stats",     's', NULL,    0, "Loop printing stats once per second" },
    { 0 }
};
static error_t parse_arg(int key, char *arg, struct argp_state *state) {
    switch (key) {
    case 'i': env.ifname = arg; break;
    case 'o': env.obj_path = arg; break;
    case 'b': env.blocklist_path = arg; break;
    case 'a': env.allowlist_path = arg; break;
    case 'g': env.generic = 1; break;
    case 's': env.stats_loop = 1; break;
    case ARGP_KEY_END:
        if (!env.ifname) argp_error(state, "missing --iface");
        break;
    default: return ARGP_ERR_UNKNOWN;
    }
    return 0;
}
static struct argp argp = { opts, parse_arg, NULL, doc };

// ---- helpers ----------------------------------------------------------------

static int libbpf_print(enum libbpf_print_level lvl, const char *fmt, va_list ap) {
    if (lvl == LIBBPF_DEBUG) return 0;   // quiet debug spam
    return vfprintf(stderr, fmt, ap);
}

// Parse "A.B.C.D" or "A.B.C.D/len" into an LPM key. Returns 0 on success.
static int parse_cidr(const char *line, struct ipv4_lpm_key *key) {
    char buf[64];
    strncpy(buf, line, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';

    char *slash = strchr(buf, '/');
    __u32 prefixlen = 32;
    if (slash) {
        *slash = '\0';
        prefixlen = (__u32)atoi(slash + 1);
        if (prefixlen > 32) return -1;
    }
    struct in_addr a;
    if (inet_pton(AF_INET, buf, &a) != 1) return -1;

    key->prefixlen = prefixlen;
    key->addr = a.s_addr;   // already network byte order
    return 0;
}

// Load blocklist file into the LPM map. Lines starting with # are comments.
static int load_blocklist(int map_fd, const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) { fprintf(stderr, "open blocklist %s: %s\n", path, strerror(errno)); return -1; }

    char line[128];
    int n = 0, bad = 0;
    while (fgets(line, sizeof(line), f)) {
        // trim leading whitespace + skip blanks/comments
        char *p = line;
        while (*p == ' ' || *p == '\t') p++;
        if (*p == '#' || *p == '\n' || *p == '\0') continue;
        // strip trailing newline
        p[strcspn(p, "\r\n")] = '\0';

        struct ipv4_lpm_key key;
        if (parse_cidr(p, &key) != 0) {
            fprintf(stderr, "  skip invalid line: %s\n", p);
            bad++;
            continue;
        }
        __u8 val = 1;
        if (bpf_map_update_elem(map_fd, &key, &val, BPF_ANY) != 0) {
            fprintf(stderr, "  map update failed for %s: %s\n", p, strerror(errno));
            bad++;
            continue;
        }
        n++;
    }
    fclose(f);
    printf("blocklist: loaded %d entries (%d skipped)\n", n, bad);
    return 0;
}

// Sum a PERCPU_ARRAY counter across all CPUs.
static __u64 read_stat(int map_fd, __u32 idx, int ncpu) {
    __u64 vals[1024];   // libbpf requires room for one value per possible CPU
    if (ncpu > 1024) ncpu = 1024;
    if (bpf_map_lookup_elem(map_fd, &idx, vals) != 0) return 0;
    __u64 sum = 0;
    for (int i = 0; i < ncpu; i++) sum += vals[i];
    return sum;
}

static void print_stats(int stats_fd, int ncpu) {
    printf("\n--- WAF stats ---\n");
    for (__u32 i = 0; i < C_MAX; i++)
        printf("  %-16s %llu\n", stat_names[i],
               (unsigned long long)read_stat(stats_fd, i, ncpu));
    fflush(stdout);
}

// ---- latency histogram ------------------------------------------------------

#define LAT_BUCKETS 64

// Pretty-print the log2-ns latency histogram.
// Each bucket i counts packets where 2^i ns <= latency < 2^(i+1) ns.
// We skip leading and trailing empty buckets for readability, and draw a
// simple ASCII bar chart scaled to the widest bar.
static void print_latency_hist(int hist_fd, int ncpu) {
    __u64 counts[LAT_BUCKETS] = {0};
    __u64 total = 0;
    __u64 max_count = 0;

    // Sum per-CPU values for every bucket.
    for (__u32 i = 0; i < LAT_BUCKETS; i++) {
        __u64 vals[1024];
        int n = ncpu < 1024 ? ncpu : 1024;
        if (bpf_map_lookup_elem(hist_fd, &i, vals) == 0) {
            __u64 sum = 0;
            for (int c = 0; c < n; c++) sum += vals[c];
            counts[i] = sum;
            total += sum;
            if (sum > max_count) max_count = sum;
        }
    }

    // Find first and last non-empty bucket.
    int first = LAT_BUCKETS, last = -1;
    for (int i = 0; i < LAT_BUCKETS; i++) {
        if (counts[i]) { if (i < first) first = i; last = i; }
    }

    printf("\n--- WAF program latency histogram (total packets: %llu) ---\n",
           (unsigned long long)total);

    if (total == 0) { printf("  (no packets recorded yet)\n"); return; }

    // Helper: format a ns value as a human-readable string.
    // Returns a static buffer — fine for single-threaded printing.
    for (int i = first; i <= last; i++) {
        // Bucket label: the lower bound is 2^i ns.
        __u64 lo_ns = (i == 0) ? 0 : (1ULL << i);
        __u64 hi_ns = (1ULL << (i + 1)) - 1;

        // Choose the most readable unit for the lower bound.
        char lo_str[24], hi_str[24];
        if (lo_ns < 1000)
            snprintf(lo_str, sizeof(lo_str), "%4lluns", (unsigned long long)lo_ns);
        else if (lo_ns < 1000000)
            snprintf(lo_str, sizeof(lo_str), "%4.1fus", (double)lo_ns / 1e3);
        else
            snprintf(lo_str, sizeof(lo_str), "%4.1fms", (double)lo_ns / 1e6);

        if (hi_ns < 1000)
            snprintf(hi_str, sizeof(hi_str), "%4lluns", (unsigned long long)hi_ns);
        else if (hi_ns < 1000000)
            snprintf(hi_str, sizeof(hi_str), "%4.1fus", (double)hi_ns / 1e3);
        else
            snprintf(hi_str, sizeof(hi_str), "%4.1fms", (double)hi_ns / 1e6);

        // ASCII bar: scale to 40 columns.
        int bar_width = (int)((counts[i] * 40) / max_count);
        char bar[41];
        for (int b = 0; b < bar_width; b++) bar[b] = '#';
        bar[bar_width] = '\0';

        double pct = total ? (100.0 * counts[i] / total) : 0.0;
        printf("  [%s .. %s) %8llu (%5.1f%%)  %s\n",
               lo_str, hi_str,
               (unsigned long long)counts[i], pct, bar);
    }

    // Print p50 / p99 / max as a convenience summary.
    __u64 p50_target = total / 2, p99_target = total * 99 / 100;
    __u64 running = 0;
    int p50_bucket = -1, p99_bucket = -1, max_bucket = last;
    for (int i = 0; i < LAT_BUCKETS; i++) {
        running += counts[i];
        if (p50_bucket < 0 && running >= p50_target)  p50_bucket = i;
        if (p99_bucket < 0 && running >= p99_target)  p99_bucket = i;
    }
    // Report the upper edge of the percentile bucket as an upper-bound estimate.
    __u64 p50_ub = p50_bucket >= 0 ? (1ULL << (p50_bucket + 1)) : 0;
    __u64 p99_ub = p99_bucket >= 0 ? (1ULL << (p99_bucket + 1)) : 0;
    __u64 max_ub = max_bucket >= 0 ? (1ULL << (max_bucket + 1)) : 0;

    printf("  p50 < %-8lluns   p99 < %-8lluns   max_bucket_ub < %lluns\n",
           (unsigned long long)p50_ub,
           (unsigned long long)p99_ub,
           (unsigned long long)max_ub);
    fflush(stdout);
}

// ---- main -------------------------------------------------------------------

int main(int argc, char **argv) {
    int err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
    if (err) return 1;

    libbpf_set_print(libbpf_print);
    signal(SIGINT, on_sigint);
    signal(SIGTERM, on_sigint);

    int ifindex = if_nametoindex(env.ifname);
    if (!ifindex) {
        fprintf(stderr, "unknown interface %s: %s\n", env.ifname, strerror(errno));
        return 1;
    }

    // Pin maps under PIN_BASEDIR by setting the object's pin_root_path.
    struct bpf_object_open_opts open_opts = {
        .sz = sizeof(open_opts),
        .pin_root_path = PIN_BASEDIR,
    };

    struct bpf_object *obj = bpf_object__open_file(env.obj_path, &open_opts);
    if (!obj || libbpf_get_error(obj)) {
        fprintf(stderr, "open %s failed (is the path right? built with -g?)\n", env.obj_path);
        return 1;
    }

    // Tell libbpf to pin every map (LIBBPF_PIN_BY_NAME) under pin_root_path.
    struct bpf_map *map;
    bpf_object__for_each_map(map, obj) {
        if (bpf_map__set_pin_path(map, NULL) != 0) {
            // set a default pin path: PIN_BASEDIR/<mapname>
            char path[256];
            snprintf(path, sizeof(path), "%s/%s", PIN_BASEDIR, bpf_map__name(map));
            bpf_map__set_pin_path(map, path);
        }
    }

    if (bpf_object__load(obj) != 0) {
        fprintf(stderr, "load/verify failed. Run with: bpftool prog load %s /sys/fs/bpf/waf/prog\n"
                        "to see the full verifier log.\n", env.obj_path);
        bpf_object__close(obj);
        return 1;
    }

    // Grab map fds by name.
    int blocklist_fd = bpf_object__find_map_fd_by_name(obj, "blocklist_v4");
    int allowlist_fd = bpf_object__find_map_fd_by_name(obj, "allowlist_v4");
    int stats_fd     = bpf_object__find_map_fd_by_name(obj, "stats");
    int hist_fd      = bpf_object__find_map_fd_by_name(obj, "latency_hist");
    if (blocklist_fd < 0 || allowlist_fd < 0 || stats_fd < 0 || hist_fd < 0) {
        fprintf(stderr, "could not find expected maps in object\n");
        bpf_object__close(obj);
        return 1;
    }

    // === PATH B ===
    // int xsks_fd = bpf_object__find_map_fd_by_name(obj, "xsks_map");
    // AF_XDP socket creation + bpf_map_update_elem(xsks_fd, &queue, &xsk_fd, 0)
    // goes here, before/after attach as appropriate.

    // Find the program and attach it.
    struct bpf_program *prog = bpf_object__find_program_by_name(obj, "xdp_waf_prog");
    if (!prog) {
        fprintf(stderr, "program xdp_waf_prog not found in object\n");
        bpf_object__close(obj);
        return 1;
    }

    // Choose attach flags: try native (DRV) first unless --generic was given.
    __u32 xdp_flags = env.generic ? XDP_FLAGS_SKB_MODE : XDP_FLAGS_DRV_MODE;

    struct bpf_link *link = NULL;
    LIBBPF_OPTS(bpf_xdp_attach_opts, aopts);
    int prog_fd = bpf_program__fd(prog);

    err = bpf_xdp_attach(ifindex, prog_fd, xdp_flags, &aopts);
    if (err && !env.generic) {
        fprintf(stderr, "native XDP attach failed (%s); retrying in generic mode\n",
                strerror(-err));
        xdp_flags = XDP_FLAGS_SKB_MODE;
        err = bpf_xdp_attach(ifindex, prog_fd, xdp_flags, &aopts);
    }
    if (err) {
        fprintf(stderr, "XDP attach failed: %s\n", strerror(-err));
        bpf_object__close(obj);
        return 1;
    }
    (void)link;

    printf("attached xdp_waf to %s (ifindex %d, %s mode)\n",
           env.ifname, ifindex,
           (xdp_flags & XDP_FLAGS_SKB_MODE) ? "generic/SKB" : "native");
    printf("maps pinned under %s\n", PIN_BASEDIR);

    if (env.blocklist_path)
        load_blocklist(blocklist_fd, env.blocklist_path);
    
    if (env.allowlist_path)
        load_blocklist(allowlist_fd, env.allowlist_path);

    int ncpu = libbpf_num_possible_cpus();
    if (ncpu < 1) ncpu = 1;

    // Print stats: once, or loop until Ctrl-C.
    if (env.stats_loop) {
        printf("streaming stats (Ctrl-C to detach)...\n");
        while (!exiting) {
            print_stats(stats_fd, ncpu);
            print_latency_hist(hist_fd, ncpu);
            sleep(1);
        }
    } else {
        print_stats(stats_fd, ncpu);
        print_latency_hist(hist_fd, ncpu);
        printf("\nprogram stays attached. Re-run with -s to stream stats,\n"
               "or Ctrl-C now to detach.\n");
        while (!exiting) pause();
    }

    // Cleanup: detach + remove pins so we leave the box as we found it.
    printf("\ndetaching...\n");
    bpf_xdp_detach(ifindex, xdp_flags, &aopts);
    bpf_object__close(obj);
    // Remove pinned maps directory contents.
    // (Best-effort; ignore errors.)
    char cmd[128];
    snprintf(cmd, sizeof(cmd), "rm -rf %s", PIN_BASEDIR);
    if (system(cmd) != 0) { /* ignore */ }
    printf("done.\n");
    return 0;
}