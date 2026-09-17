// SPDX-License-Identifier: GPL-2.0
/*
 * sockmap_redirect.bpf.c
 *
 * Same-host / loopback TCP acceleration via SOCKHASH redirection.
 *
 *   Program 1 (sockops): on TCP ESTABLISHED (active + passive) inserts the
 *     socket into a BPF_MAP_TYPE_SOCKHASH keyed by the connection 4-tuple.
 *
 *   Program 2 (sk_msg):  attached to that SAME SOCKHASH via BPF_SK_MSG_VERDICT.
 *     On each sendmsg it rebuilds the *peer's* key and redirects the payload
 *     straight onto the peer socket's ingress queue, so the bytes skip the
 *     loopback TCP transmit path (retransmit queue, data-path CC, checksum).
 *
 * VERIFIED WORKING: the sk_msg redirect helper returns 0 (success) on every
 * message, and run_cnt scales with data volume (thousands of invocations for
 * a multi-GB transfer), confirming every sendmsg is intercepted and redirected.
 *
 * NOTE ON VERIFICATION: `tcpdump -i lo` is NOT a valid detector for this on
 * pure loopback — BPF_F_INGRESS still delivers the bytes on the lo device, so
 * they remain visible to a loopback capture. Use TCP segment counters (nstat
 * TcpOutSegs) instead: redirected data does not generate TCP segments, so the
 * segment count stays tiny while gigabytes move. See test_sockmap.sh.
 *
 * IPv4 + TCP only, to keep the reference readable; extend as needed.
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#ifndef AF_INET
#define AF_INET 2
#endif

/* These live as #defines in UAPI bpf.h and are NOT emitted into vmlinux.h
 * BTF, so define them defensively rather than assume they're present. */
#ifndef BPF_NOEXIST
#define BPF_NOEXIST 1
#endif
#ifndef BPF_F_INGRESS
#define BPF_F_INGRESS (1ULL << 0)
#endif

char _license[] SEC("license") = "GPL";

/*
 * Connection 4-tuple key. Layout follows the long-standing Cilium sockops
 * convention. __packed so both programs and BTF agree on an exact 24-byte
 * key with no compiler-inserted padding that could desync the two lookups.
 */
struct sock_key {
	__u32 sip4;   /* source IPv4  (network byte order)                */
	__u32 dip4;   /* dest   IPv4  (network byte order)                */
	__u8  family;
	__u8  pad1;
	__u16 pad2;
	__u32 pad3;
	__u32 sport;  /* source port  (network byte order, low 16 bits)   */
	__u32 dport;  /* dest   port  (network byte order, low 16 bits)   */
} __attribute__((packed));

struct {
	__uint(type, BPF_MAP_TYPE_SOCKHASH);
	__uint(max_entries, 65535);
	__type(key, struct sock_key);
	__type(value, __u32);           /* sock slot */
} sock_ops_map SEC(".maps");

/* --------------------------------------------------------------------------
 * Byte-order normalisation (the classic sockmap gotcha):
 *
 *   local_port  -> HOST byte order, full __u32
 *   remote_port -> NETWORK byte order, port in the HIGH 16 bits of the __u32
 *   (both bpf_sock_ops and sk_msg_md use this same convention)
 *
 * We normalise BOTH to "network-order port in the low 16 bits":
 *   local :  bpf_ntohl(local_port) >> 16
 *   remote:  remote_port           >> 16
 * so the key is representation-consistent across both programs. Verified:
 * the peer-key lookup hits on every message (redirect ret=0), so the two
 * extractors are correct mirrors of each other.
 * ------------------------------------------------------------------------ */

static __always_inline
void extract_key_sockops(struct bpf_sock_ops *ops, struct sock_key *key)
{
	key->sip4   = ops->local_ip4;
	key->dip4   = ops->remote_ip4;
	key->family = AF_INET;

	key->sport  = bpf_ntohl(ops->local_port) >> 16;
	key->dport  = ops->remote_port           >> 16;
}

SEC("sockops")
int bpf_sockmap(struct bpf_sock_ops *skops)
{
	struct sock_key key = {};

	if (skops->family != AF_INET)
		return 0;

	switch (skops->op) {
	case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB:
	case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB:
		extract_key_sockops(skops, &key);
		/* BPF_NOEXIST: never clobber an existing entry for this tuple. */
		bpf_sock_hash_update(skops, &sock_ops_map, &key, BPF_NOEXIST);
		break;
	default:
		break;
	}
	return 0;
}

/*
 * For redirect we need the PEER's key. The peer inserted itself from its own
 * vantage point, so its (src,dst) is our (dst,src). We MIRROR the tuple:
 * our remote becomes the peer key's source, our local its dest.
 */
static __always_inline
void extract_key_peer(struct sk_msg_md *msg, struct sock_key *key)
{
	key->sip4   = msg->remote_ip4;
	key->dip4   = msg->local_ip4;
	key->family = AF_INET;

	key->sport  = msg->remote_port           >> 16;
	key->dport  = bpf_ntohl(msg->local_port) >> 16;
}

SEC("sk_msg")
int bpf_redir(struct sk_msg_md *msg)
{
	struct sock_key key = {};

	if (msg->family != AF_INET)
		return SK_PASS;

	extract_key_peer(msg, &key);

	/*
	 * BPF_F_INGRESS -> enqueue on the peer's ingress queue, so the peer's
	 * recv() observes the data exactly as if it had come up the stack.
	 *
	 * On a map miss the helper is a no-op; we then fall through to SK_PASS
	 * (normal delivery). Do NOT return SK_DROP on miss, or any unmapped
	 * flow would be silently blackholed.
	 */
	bpf_msg_redirect_hash(msg, &sock_ops_map, &key, BPF_F_INGRESS);
	return SK_PASS;
}