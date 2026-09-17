#!/usr/bin/env bash
# trace_run.sh — run the test while capturing the BPF trace, in one terminal.
#
# Produces /tmp/sockmap_trace.txt with the bpf_printk output from both programs.
# Read that file (or paste it) to see whether inserts and redirects succeed.
set -uo pipefail
[ "$(id -u)" -eq 0 ] || { echo "run as root: sudo ./trace_run.sh"; exit 1; }

TRACE=/sys/kernel/debug/tracing/trace_pipe
OUT=/tmp/sockmap_trace.txt

# Make sure tracefs is mounted (it usually is on Kali).
if [ ! -e "$TRACE" ]; then
  mount -t tracefs nodev /sys/kernel/debug/tracing 2>/dev/null || {
    echo "cannot access $TRACE — is tracefs available?"; exit 1; }
fi

# Clear any stale trace, then start draining it into a file in the background.
: > /sys/kernel/debug/tracing/trace 2>/dev/null || true
: > "$OUT"
timeout 30 cat "$TRACE" > "$OUT" 2>/dev/null &
CATPID=$!

echo "===== capturing trace to $OUT ====="
# Run the actual test (its own output still prints to your terminal).
./test_sockmap.sh

# Give the trace a beat to flush, then stop the capture.
sleep 1
kill "$CATPID" 2>/dev/null || true
wait "$CATPID" 2>/dev/null || true

echo
echo "===== BPF trace lines (SOCKOPS = inserts, SKMSG = redirects) ====="
grep -E 'SOCKOPS|SKMSG' "$OUT" | head -40
echo "..."
echo "Full trace saved at $OUT"
echo
echo "How to read it:"
echo "  SOCKOPS ... ret=0     -> insert succeeded"
echo "  SOCKOPS ... ret=-17   -> EEXIST (entry already present)"
echo "  (no SOCKOPS lines)    -> sockops hook never fired (cgroup/attach issue)"
echo "  SKMSG   ... ret=0     -> redirect HIT (bytes went to peer ingress) <-- want this"
echo "  SKMSG   ... ret=-<n>  -> redirect MISS/fail (this is the bug, code names why)"