# Kernel-Level Machine Learning DDoS Protection using eBPF/XDP

This project implements a standalone, highly optimized Intrusion Detection System (IDS) that runs entirely inside the Linux Kernel using eBPF (Extended Berkeley Packet Filter) and XDP (eXpress Data Path). 

Unlike traditional security tools that analyze traffic in userspace (like Suricata or Snort), this system runs a **fully functioning Artificial Neural Network (trained in PyTorch)** directly within the kernel. It intercepts, mathematically analyzes, and drops malicious DDoS packets before they even reach the Linux networking stack, providing zero-latency protection.

## Features

- **Zero-Latency Mitigation**: Packets are analyzed and dropped at the network interface layer (XDP), saving massive amounts of CPU and memory compared to userspace firewalls.
- **3-Layer Detection Engine**: Combines a global destination-based heuristic (distributed attacks), a per-source whitelist (false positive protection), and a per-source ML model (concentrated attacks) for comprehensive DDoS coverage.
- **Pure-C Neural Network Inference**: The PyTorch model weights are transpiled into pure C fixed-point mathematics.
- **Branchless Math Optimization**: Uses advanced eBPF verifier bypass techniques (like inline BPF assembly `s>>= 63` and volatile masking) to prevent state explosion and easily bypass the 1,000,000 instruction complexity limit.
- **Standalone Execution**: No Python background daemons or userspace feature injection required. The XDP program tracks packet statistics (Inter-Arrival Time, Length Variance, etc.) autonomously using BPF Hash Maps.
- **CIC-IDS2017 Trained**: The model is trained to recognize the statistical flow footprints of real-world SYN, ACK, and HTTP floods.

## Detection Architecture

The system uses a **3-layer decision engine** that processes every packet:

```
Packet arrives at XDP
    │
    ├─► LAYER 1 — Global Destination Check
    │   Is (dst_ip, dst_port) under aggregate DDoS attack?
    │   Uses a 256-bit bloom filter bitmap to count unique sources
    │   and a 1-second time window for packet rate.
    │       NO  → go to Layer 3 (normal per-source ML)
    │       YES ↓
    │
    ├─► LAYER 2 — Whitelist & SYN Cookie (only during active attack)
    │   Is src_ip in whitelist AND not expired?
    │       YES → XDP_PASS (verified legitimate user)
    │       NO  → Is packet a SYN?
    │             ├─► Failed 5 times? → PENALTY BOX (XDP_DROP)
    │             └─► Else → XDP_TX (Send Cryptographic SYN-ACK Challenge)
    │       NO  → Is packet an ACK?
    │             ├─► Solved Puzzle? → Add to Whitelist
    │             └─► Else → XDP_DROP
    │
    ├─► LAYER 3 — Per-Source ML Inference (normal operation)
    │   Run neural network on this src_ip's flow statistics.
    │       Benign → XDP_PASS + add to whitelist (30s TTL)
    │       Attack → XDP_DROP
```

### Why 3 Layers?

- **Layer 1 (Global Heuristic)** catches **distributed DDoS** attacks from many sources (e.g., 100 attackers each sending moderate traffic). Individual flows look benign, but the aggregate rate + source diversity is clearly malicious.
- **Layer 2 (Whitelist & SYN Cookies)** protects **legitimate users** during a distributed attack. Sources verified by the ML model before the attack get a 5-minute grace period. Unverified new users are challenged with a pure-eBPF cryptographic **SYN Cookie (First Packet Authentication)**. Bots failing the puzzle 5 times are permanently dropped via a **Penalty Box** to eliminate outbound traffic amplification.
- **Layer 3 (Per-Source ML)** catches **concentrated DDoS** attacks from few sources (e.g., 5 attackers each sending massive traffic). The neural network detects anomalous per-flow statistics.

## Machine Learning Model Details

The system uses a highly optimized, fully connected Neural Network (Multi-Layer Perceptron) designed specifically to pass the strict eBPF verifier limits while maintaining high accuracy.

- **Architecture**: 
  - Input Layer: 8 Neurons (Network Features)
  - Hidden Layer: 16 Neurons
  - Output Layer: 1 Neuron (Binary Classification: Benign vs. DDoS)
- **Extracted Features**: The eBPF program calculates 8 live flow statistics per IP address: `Destination Port`, `Packet Length Mean`, `Packet Length StdDev`, `Forward IAT Mean`, `Forward IAT StdDev`, `Max IAT`, `Flow Duration`, and `Init_Win_Bytes_Forward`.
- **Activation Function**: A branchless `ReLU` (Rectified Linear Unit) is used to prevent the eBPF verifier from splitting execution paths.
- **Data Scaling**: Floating-point Standard Scalers (from `scikit-learn`) are implemented using **24-bit fixed-point compile-time bitshifting**. This completely eliminates division operations in the kernel, preserving mathematical precision without triggering the BPF division-by-zero checks.
- **Logit Threshold**: The final output logit applies a threshold of `123` (equivalent to `> 0.53` Sigmoid probability) to aggressively classify anomalous traffic as a DDoS flood.

## Supported DDoS Mitigations

### Concentrated Attacks (Layer 3 — Per-Source ML)
- **TCP SYN Floods**: Blocks rapid connection requests before the kernel allocates half-open connection memory.
- **TCP ACK Floods**: Drops unsolicited acknowledgement floods designed to exhaust state-table resources.
- **TCP FIN & XMAS Floods**: Blocks invalid TCP flag combinations sent at high speeds.
- **HTTP GET Floods (Botnets)**: Blocks application-layer DDoS attacks by mathematically recognizing the non-human Inter-Arrival Times (IAT) and packet sizes generated by botnet scripts like Apache Benchmark (`ab`) or GoldenEye.

### Distributed Attacks (Layer 1 — Global Heuristic)
- **Distributed SYN Floods**: Detects when 10+ unique source IPs flood the same destination port simultaneously, even if each individual source sends moderate traffic.
- **Botnet Swarm Attacks**: Catches coordinated attacks from 100+ sources where each source's individual flow appears benign but the aggregate volume is clearly malicious.
- **Low-and-Slow Distributed Floods**: Detected via the combination of source diversity and aggregate packet rate thresholds.

*Note: The current C code is optimized for TCP. Volumetric UDP Floods and ICMP (Ping) Floods are instantly bypassed (`XDP_PASS`) to save verifier complexity, but could easily be added by extending the packet parser.*

## Tunable Thresholds

The global heuristic detector uses configurable `#define` constants in `xdp_model.c`:

| Constant | Default | Purpose |
|---|---|---|
| `GLOBAL_PKT_RATE_THRESHOLD` | 1000 | Packets/sec to trigger global alert |
| `GLOBAL_SRC_DIVERSITY_THRESH` | 10 | Minimum unique sources to confirm "distributed" |
| `WINDOW_DURATION_US` | 1,000,000 | Time window for rate counting (1 second) |
| `WHITELIST_TTL_US` | 30,000,000 | How long a verified source stays whitelisted (30 seconds) |

> **Mininet Tip**: For Mininet testing, the default values of 1000 pkt/s and 10 sources are appropriate. For production servers, increase `GLOBAL_PKT_RATE_THRESHOLD` to match your normal traffic baseline.

## Performance & Latency

Because the Neural Network is compiled directly into eBPF bytecode and executes in the kernel's XDP hook, the performance is mathematically bounded by raw CPU clock cycles.

By measuring the exact hardware clock using `bpf_ktime_get_ns()`, the entire ML Inference Engine processes a packet in **22 to 39 nanoseconds**.

- **Why is it so fast?** The C compiler unrolls the PyTorch matrix multiplications into a flat array of bare-metal ALU instructions. There are no branches, no memory jumping, and no Python runtime. A modern 3GHz CPU processes this math in roughly 80 clock cycles.
- **Application Latency:** Legitimate traffic passing through the XDP filter experiences practically **zero measurable latency overhead** (less than 1 millisecond), making this a highly viable solution for massive-scale edge servers.
- **Global Heuristic Overhead**: The Layer 1 bloom filter check adds approximately 150 instructions (~5 nanoseconds), negligible compared to the ML inference.

## Project Structure

- `xdp_model.c`: The core C codebase. Contains the 3-layer detection engine: global heuristic, whitelist, packet parser, state tracker, statistical feature extractor, and Neural Network inference engine.
- `src/model_weights.h`: The auto-generated neural network matrices (weights, biases) and standard scaler parameters exported from PyTorch.
- `load_xdp.sh`: The main deployment script. Compiles the C code into eBPF bytecode using Clang and attaches it to the interface using `iproute2`.
- `model.ipynb` / `hardcore_test.py`: The original Python environment used to train the model on the CIC-IDS2017 dataset.

## Setup & Deployment

1. **Compile and Load the Model**
   Run the deployment script to compile the XDP program and attach it to your loopback (`lo`) interface:
   ```bash
   sudo ./load_xdp.sh
   ```

2. **Monitor the Kernel Logs**
   Open a dedicated terminal to watch all 3 detection layers make decisions in real-time. (Logs are rate-limited during floods to prevent kernel tracing DoS).
   ```bash
   sudo cat /sys/kernel/debug/tracing/trace_pipe
   ```
   
   You will see messages like:
   - `DISTRIBUTED DDoS! 1500 pkts, ~42 sources` — Layer 1 triggered
   - `GLOBAL DDoS: Blocked unverified IP, 10000 pkts` — Layer 2 blocking during attack
   - `DDoS DETECTED! Dropped 10000 packets.` — Layer 3 ML detection
   - `ML Inference Latency: 28 nanoseconds` — Per-packet ML timing

## How to Test

Once the model is loaded, you can test its ability to differentiate between legitimate users and malicious botnets.

### 1. Start a Dummy Server
In a new terminal, start a basic Python web server on port 8080:
```bash
sudo python3 -m http.server 8080
```

### 2. Simulate Legitimate Traffic
Act like a normal user making web requests:
```bash
watch -n 1 curl -s http://127.0.0.1:8080/
```
*Notice that your web server responds successfully and the kernel logs remain silent. The Neural Network predicts Benign (0) and whitelists the source.*

### 3. Launch a Concentrated Attack (Few Attackers)
While the legitimate traffic is running, launch a massive SYN flood from a spoofed IP address (`9.9.9.9`) to simulate a hacker:
```bash
sudo hping3 -S -p 8080 -a 9.9.9.9 --flood 127.0.0.1
```
*Look at your kernel logs! The ML model (Layer 3) will mathematically recognize the malicious flow timings of the spoofed IP and instantly begin dropping the attack packets. Your legitimate `curl` requests will continue to work flawlessly.*

### 4. Launch a Distributed Attack (Many Attackers — Mininet)
In a Mininet topology with 100 attacker hosts:
```python
# From each attacker host:
h.cmd('hping3 -S -p 8080 --flood 10.0.0.1 &')
```
*The global heuristic (Layer 1) will detect 100+ unique sources flooding port 8080 and activate distributed DDoS mode. All unverified sources are blocked. Your previously whitelisted legitimate traffic continues uninterrupted via Layer 2.*

## Unloading

To remove the ML model from the kernel and restore normal traffic flow:
```bash
sudo ip link set dev lo xdp off
```
