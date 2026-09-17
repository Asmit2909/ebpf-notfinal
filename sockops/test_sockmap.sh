#!/usr/bin/env bash
# test_sockmap.sh — bring-up, functional proof, and throughput test.
#
# Requires root + cgroup v2 + a BTF-enabled kernel.
# Tools: bpftool, clang, iperf3, nstat (from iproute2).
#
# PROOF METHOD (important): we use TCP *segment counters* (TcpOutSegs from
# /proc/net/snmp), NOT tcpdump-on-lo. On pure loopback, BPF_F_INGRESS redirect
# still delivers bytes on the lo device, so a loopback capture still sees them
# -- that makes "proof by absence on lo" a false negative. The correct signal
# is that redirected data does NOT generate TCP segments: gigabytes move while
# TcpOutSegs grows by only a small number (handshake/ACK/FIN control segments).
set -uo pipefail

OBJ=sockmap_redirect.bpf.o
PIN=/sys/fs/bpf/sm
CG=/sys/fs/cgroup/sockmap_test
PORT=5599
BYTES_TARGET_GB=3

need(){ command -v "$1" >/dev/null || { echo "missing tool: $1"; exit 1; }; }
need bpftool; need clang; need iperf3; need make
[ "$(id -u)" -eq 0 ] || { echo "run as root"; exit 1; }

if [ ! -f /sys/fs/cgroup/cgroup.controllers ]; then
  echo "ERROR: cgroup v2 unified hierarchy not found at /sys/fs/cgroup."
  exit 1
fi

in_cg(){ ( echo $BASHPID > "$CG/cgroup.procs"; exec "$@" ); }

# In /proc/net/snmp the "Tcp:" data row columns are:
#   $11 = InSegs, $12 = OutSegs.  On loopback both move together (every segment
#   sent is also received), but we track OutSegs as the transmit-path signal.
tcp_outsegs(){ awk '/^Tcp:/ && $2 ~ /^[0-9]/ {print $12}' /proc/net/snmp; }

cleanup(){
  set +e
  bpftool cgroup detach "$CG" sock_ops pinned "$PIN/bpf_sockmap" 2>/dev/null
  rm -rf "$PIN"
  echo $$ > /sys/fs/cgroup/cgroup.procs 2>/dev/null
  [ -d "$CG" ] && rmdir "$CG" 2>/dev/null
  sysctl -q -w kernel.bpf_stats_enabled=0
  pkill -f "iperf3 -s -1 -p $PORT" 2>/dev/null
}
trap cleanup EXIT

# --- build -------------------------------------------------------------------
make --no-print-directory "$OBJ"

# --- BASELINE: plain loopback, measure segments for the transfer -------------
echo "===== BASELINE (plain loopback TCP, no redirect) ====="
iperf3 -s -1 -p "$PORT" >/dev/null 2>&1 & sleep 0.4
B0=$(tcp_outsegs)
iperf3 -c 127.0.0.1 -p "$PORT" -n "${BYTES_TARGET_GB}G" -f g | grep -E "sender|receiver"
B1=$(tcp_outsegs)
BASE_SEGS=$(( B1 - B0 ))
printf "baseline TcpOutSegs delta: %'d  (expect MILLIONS for %s GB)\n" "$BASE_SEGS" "$BYTES_TARGET_GB"

# --- load + attach both hooks ------------------------------------------------
rm -rf "$PIN"; mkdir -p "$CG"
sysctl -q -w kernel.bpf_stats_enabled=1
bpftool prog loadall "$OBJ" "$PIN" pinmaps "$PIN"
bpftool cgroup attach "$CG" sock_ops pinned "$PIN/bpf_sockmap"
bpftool prog attach pinned "$PIN/bpf_redir" msg_verdict pinned "$PIN/sock_ops_map"
echo "===== ATTACHED ====="
bpftool cgroup show "$CG"

# --- REDIRECT: same transfer, both endpoints in the cgroup -------------------
in_cg iperf3 -s -1 -p "$PORT" >/dev/null 2>&1 & SRV=$!
sleep 0.4
echo "===== REDIRECT (sockmap active) ====="
R0=$(tcp_outsegs)
in_cg iperf3 -c 127.0.0.1 -p "$PORT" -n "${BYTES_TARGET_GB}G" -f g | grep -E "sender|receiver"
R1=$(tcp_outsegs)
REDIR_SEGS=$(( R1 - R0 ))
wait "$SRV" 2>/dev/null || true

# --- evidence ----------------------------------------------------------------
echo
echo "===== sockhash entries (during transfer; often 0 after sockets close) ====="
bpftool map dump pinned "$PIN/sock_ops_map" | grep -c '^key' || true

echo "===== sk_msg prog run_cnt (expect THOUSANDS -- one per sendmsg) ====="
bpftool prog show pinned "$PIN/bpf_redir" | grep -o 'run_cnt [0-9]*' || \
  echo "run_cnt not shown (is kernel.bpf_stats_enabled=1?)"

echo
echo "=============================================================="
echo "  THE PROOF: TCP segments for the SAME ${BYTES_TARGET_GB} GB transfer"
echo "=============================================================="
printf "  baseline (no redirect): %'d segments\n" "$BASE_SEGS"
printf "  redirect (sockmap on) : %'d segments\n" "$REDIR_SEGS"
echo "--------------------------------------------------------------"
if [ "$REDIR_SEGS" -gt 0 ]; then
  ratio=$(( BASE_SEGS / REDIR_SEGS ))
  echo "  redirect used ~${ratio}x FEWER TCP segments for the same bytes."
fi
echo
echo "  Interpretation:"
echo "   - redirect WORKING  -> redirect segments are a tiny fraction of"
echo "     baseline (data bypasses the TCP transmit path; control segs remain)."
echo "   - redirect NOT working -> the two numbers would be similar,"
echo "     both scaling with bytes/MSS."