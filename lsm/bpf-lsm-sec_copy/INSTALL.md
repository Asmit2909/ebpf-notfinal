# BPF-LSM-SEC Offline Installation Guide

This guide will walk you through installing the eBPF Security Daemon on an offline machine (e.g. an air-gapped Ubuntu server).

## 1. Transfer the Bundle
Copy the `bpf-sec-offline.tar.gz` file to a USB drive and transfer it to the offline PC.

## 2. Extract the Bundle
On the offline PC, first combine the split files into a single tarball, and then extract them:
```bash
cat bpf-sec-offline.tar.gz.part-* > bpf-sec-offline.tar.gz
tar -xzvf bpf-sec-offline.tar.gz
cd offline_bundle
```

## 3. Run the Automated Installer
The bundle comes with an `install.sh` script that handles all the offline installations for you. 
You must run this as `root` (or with `sudo`):

```bash
sudo ./install.sh
```

**What this script does:**
1. Installs the Clang/LLVM compilers from the `.deb` files (required for dynamic sensors).
2. Installs Go from the local Snap files (`go_*.assert` and `go_*.snap`).
3. Copies the pre-compiled `bpf-sec-daemon` to `/usr/local/bin/`.
4. Sets up the default configuration file at `/etc/bpf-sec-policy.yaml`.

## 4. Verify the Installation
After the script completes, you can verify that the daemon is installed by running:

```bash
sudo bpf-sec-daemon /etc/bpf-sec-policy.yaml
```

If it starts successfully and prints `Bootstrapped process tree into eBPF map`, your installation is complete!

---

## (Optional) Re-compiling the Code Offline
If you decide to modify the Go source code (located in the `src/` directory), you can recompile it entirely offline. 

Because we included the `vendor/` directory, you just need to tell Go to use the offline modules:
```bash
cd src/
make build
```
*(The Makefile is already configured to use `-mod=vendor` for offline builds!)*
