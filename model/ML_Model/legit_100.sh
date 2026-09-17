#!/bin/bash
# Launch legitimate curl requests from Mininet hosts h2-h100
# to test if legitimate traffic gets blocked.

TARGET="10.0.0.254"
PORT=8080

echo "[*] Launching legitimate curl requests from 99 hosts simultaneously..."

for i in $(seq 2 100); do
    PID=$(pgrep -f "mininet:h${i}$" | head -1)
    if [ -n "$PID" ]; then
        # Run curl in the background so they all hit at the exact same time
        nsenter -t "$PID" -n -- curl -s -o /dev/null -w "h$i: HTTP %{http_code}\n" --max-time 5 http://$TARGET:$PORT/ &
    fi
done

# Wait for all background curls to finish
wait
echo "[*] All legitimate requests completed! Check if any timed out (failed to print HTTP 200)."
