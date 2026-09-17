#!/bin/bash

echo "======================================"
echo " BPF-LSM-SEC Offline Installer"
echo "======================================"

if [ "$EUID" -ne 0 ]; then
  echo "Please run this installer as root (sudo ./install.sh)"
  exit
fi

echo "[*] Installing offline .deb packages (Clang, LLVM, LibBPF)..."
cd debs
dpkg -i *.deb
cd ..

echo "[*] Installing Go via Snap (for offline recompilation)..."
if [ -d "snaps" ] && [ "$(ls -A snaps 2>/dev/null)" ]; then
    snap ack snaps/go_*.assert
    snap install snaps/go_*.snap --classic
else
    echo "    Snap files not found. Skipping Go installation."
fi

echo "[*] Installing bpf-sec-daemon to /usr/local/bin..."
cp bpf-sec-daemon /usr/local/bin/
chmod +x /usr/local/bin/bpf-sec-daemon

echo "[*] Copying default policy.yaml to /etc/bpf-sec-policy.yaml..."
if [ ! -f /etc/bpf-sec-policy.yaml ]; then
    cp policy.yaml /etc/bpf-sec-policy.yaml
else
    echo "    /etc/bpf-sec-policy.yaml already exists, skipping overwrite."
fi

echo "[*] Installation Complete!"
echo ""
echo "You can now run the daemon using:"
echo "sudo bpf-sec-daemon /etc/bpf-sec-policy.yaml"
echo "======================================"
