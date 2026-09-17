#!/bin/bash
echo "[*] Starting a dummy web server on port 8080..."
python3 -m http.server 8080 > /dev/null 2>&1 &
SERVER_PID=$!

# Ensure server stops when script exits
trap "kill $SERVER_PID; echo '[*] Stopped web server'" EXIT

sleep 1
echo "============================================="
echo " Sending traffic to port 8080 every second..."
echo "============================================="

while true; do
    # -w extracts the http code, -o /dev/null hides the HTML
    RESPONSE=$(curl -4 -s -o /dev/null -w "%{http_code}" -m 1 http://127.0.0.1:8080)
    
    if [ "$RESPONSE" = "200" ]; then
        echo -e "[\e[32mPASS\e[0m] Traffic went through successfully! (Kernel allowed it)"
    else
        echo -e "[\e[31mDROP\e[0m] Connection timed out! (Kernel XDP blocked it instantly)"
    fi
    sleep 1
done
