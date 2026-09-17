#!/usr/bin/env bash
# diagnose.sh — figure out WHY the sockmap redirect isn't diverting bytes.
# Runs two checks and prints a verdict. Run from the dir with the .bpf.o.
set -uo pipefail
[ "$(id -u)" -eq 0 ] || { echo "run as root: sudo ./diagnose.sh"; exit 1; }

OBJ=sockmap_redirect.bpf.o
PIN=/sys/fs/bpf/sm_diag
CG=/sys/fs/cgroup/sockmap_diag
PORT=5601
[ -f "$OBJ" ] || { echo "missing $OBJ — run 'make' first"; exit 1; }

cleanup(){
  set +e
  bpftool cgroup detach "$CG" sock_ops pinned "$PIN/bpf_sockmap" 2>/dev/null
  rm -rf "$PIN"
  echo $$ > /sys/fs/cgroup/cgroup.procs 2>/dev/null
  rmdir "$CG" 2>/dev/null
  pkill -f "iperf3 -s -1 -p $PORT" 2>/dev/null
}
trap cleanup EXIT

echo "################ CHECK B: kernel + feature sanity ################"
echo "kernel: $(uname -r)"
echo "--- sk_msg / sockhash feature probe ---"
bpftool feature probe 2>/dev/null | grep -Ei 'sk_msg|msg_redirect|sockhash|sockmap' \
  || echo "(no matching feature lines in probe output)"
echo "--- relevant kernel config ---"
{ zcat /proc/config.gz 2>/dev/null || cat /boot/config-"$(uname -r)" 2>/dev/null; } \
  | grep -Ei 'BPF_STREAM_PARSER|NET_SOCK_MSG|CONFIG_BPF_SYSCALL' \
  || echo "(kernel config not readable — not fatal)"

echo
echo "################ CHECK A: live map dump DURING transfer ################"
rm -rf "$PIN"; mkdir -p "$CG"
bpftool prog loadall "$OBJ" "$PIN" pinmaps "$PIN"
bpftool cgroup attach "$CG" sock_ops pinned "$PIN/bpf_sockmap"
bpftool prog attach pinned "$PIN/bpf_redir" msg_verdict pinned "$PIN/sock_ops_map"

( echo $BASHPID > "$CG/cgroup.procs"; exec iperf3 -s -1 -p "$PORT" >/dev/null 2>&1 ) &
sleep 0.5
( echo $BASHPID > "$CG/cgroup.procs"; exec iperf3 -c 127.0.0.1 -p "$PORT" -t 10 >/dev/null 2>&1 ) &
CLI=$!
sleep 2

echo "--- sockhash entries DURING transfer (raw) ---"
bpftool map dump pinned "$PIN/sock_ops_map"
N=$(bpftool map dump pinned "$PIN/sock_ops_map" | grep -c '^key')
echo "--- entry count: $N ---"

wait "$CLI" 2>/dev/null || true

echo
echo "################ VERDICT ################"
if [ "$N" -ge 2 ]; then
  echo "Both directions ARE hashed ($N entries). The map is populated correctly,"
  echo "so the non-bypass is NOT a missing-peer problem. Likely the kernel is"
  echo "delivering redirected data back through the normal path anyway (a known"
  echo "constraint of sk_msg ingress redirect between two loopback TCP sockets"
  echo "on some kernels). Next step: test redirect across a Unix-domain or"
  echo "cross-veth pair instead of loopback TCP, where the bypass is observable."
elif [ "$N" -eq 1 ]; then
  echo "Only ONE direction hashed. The redirect helper returns 0 but has no"
  echo "valid peer socket to inject into -> bytes fall through to normal TCP."
  echo "This fully explains the unchanged segment count. Fix: ensure BOTH the"
  echo "active and passive sockets insert (check the PASSIVE_ESTABLISHED case"
  echo "is firing — some setups need BPF_SOCK_OPS_STATE_CB or a parser prog)."
else
  echo "ZERO entries even during transfer. The sockops insert is not landing."
  echo "Either the cgroup attach isn't taking, or ESTABLISHED callbacks aren't"
  echo "being requested. That's the thing to fix first."
fi