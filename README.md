# Hyperion XDP: Kernel-Space Defense Engine

```console
root@Hyperion-Edge:~# ./hyperion_ctrl --load --interface=eth0

 [ BPF  ] VERIFYING BYTECODE ........................... [SAFE]
 [ JIT  ] ENABLING JIT COMPILER ........................ [ON]
 [ MAP  ] PINNING POLICY MAPS .......................... [/sys/fs/bpf/hyp_pol]
 [ XDP  ] ATTACHING TO NIC ............................. [NATIVE MODE]

  ██╗  ██╗██╗   ██╗██████╗ ███████╗██████╗ ██╗ ██████╗ ███╗   ██╗
  ██║  ██║╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗██║██╔═══██╗████╗  ██║
  ███████║ ╚████╔╝ ██████╔╝█████╗  ██████╔╝██║██║   ██║██╔██╗ ██║
  ██╔══██║  ╚██╔╝  ██╔═══╝ ██╔══╝  ██╔══██╗██║██║   ██║██║╚██╗██║
  ██║  ██║   ██║   ██║     ███████╗██║  ██║██║╚██████╔╝██║ ╚████║
  ╚═╝  ╚═╝   ╚═╝   ╚═╝     ╚══════╝╚═╝  ╚═╝╚═╝ ╚═════╝ ╚═╝  ╚═══╝
   
  >> EBPF/XDP HIGH-PERFORMANCE PACKET FILTER <<

  [RUNTIME STATUS]
  > MILESTONE:      M4.6 (Dynamic Policy + Ring Buffer)
  > ENGINE:         eBPF/XDP (Restricted C)
  > CONTROLLER:     Go (Cilium Library)
  > LICENSE:        GPLv2 (Kern) / MIT (User)
  > TARGET:         Cybersecurity Research Artifact

```

---

## [ 0x01 ] ABSTRACT

**Hyperion** is a high-performance network security engine designed to enforce content-aware policy at the NIC driver level. Unlike traditional firewalls that operate at the socket layer (Netfilter), Hyperion uses **eBPF (Extended Berkeley Packet Filter)** and **XDP (Express Data Path)** to reject malicious payloads before the Linux Kernel allocates memory (sk_buff).

> **Research Context:** This project serves as the Network Satellite to the [Sentinel Runtime](https://github.com/nevinshine/sentinel-runtime) (Host Anchor). It explores the unification of process-level and packet-level defense.

### The Research Question

> *Can we inspect packet payloads for malicious signatures at wire speed (O(N)), dropping threats before the OS commits resources?*

---

## [ 0x02 ] SYSTEM ARCHITECTURE

Hyperion operates on a split-plane design, utilizing the driver's interrupt context for maximum throughput.

### The "Two Towers" Defense

Hyperion complements Sentinel by securing the transport boundary.

| DIMENSION | SENTINEL (The Host) | HYPERION (The Wire) |
| --- | --- | --- |
| **Boundary** | Process Execution | Network Transport |
| **Mechanism** | `ptrace` / Kernel Modules | `eBPF` / `XDP` |
| **Visibility** | Syscalls (`execve`, `open`) | Payloads (`GET /hack`) |
| **Constraint** | Context-Aware Logic | Sub-microsecond Latency |

### Component Logic

| COMPONENT | TECH STACK | RESPONSIBILITY |
| --- | --- | --- |
| **KERNEL ENFORCER** | Restricted C | **The Muscle.** Parses Layer 7 payloads in the driver. Implements verifier-safe bounded loops for Deep Packet Inspection (DPI). |
| **USER CONTROLLER** | Go (Cilium) | **The Brain.** Orchestrates BPF lifecycle. Handles `SIGHUP` for zero-downtime policy reloads via BPF Maps. |
| **TELEMETRY** | Ring Buffer | **The Nerves.** Streams structured binary events from Kernel to User Space for forensic logging. |

---

## [ 0x03 ] CAPABILITY MILESTONES

We define success through distinct capability milestones.

| PHASE | GOAL | STATUS | OUTCOME |
| --- | --- | --- | --- |
| **M0** | Foundation | ✅ | `XDP_PASS` skeleton compiling with Clang/LLVM. |
| **M1** | Stateless Filtering | ✅ | Validated `XDP_DROP` against hardcoded IP targets. |
| **M2** | Stateful Tracking | ✅ | Volumetric flood detection via `BPF_MAP_TYPE_LRU_HASH`. |
| **M3** | Static DPI | ✅ | Layer 7 Payload Analysis scanning for signatures. |
| **M4** | Dynamic Policy | ✅ | **[COMPLETED]** Hot-swappable rules via `BPF_MAP_TYPE_ARRAY` & SIGHUP. |
| **M5** | Telemetry | ✅ | **[COMPLETED]** Ring Buffer telemetry with 5-tuple flow tracking. |

---

## [ 0x04 ] RESEARCH & ENGINEERING CHALLENGES

### 1. Verifier-Safe Deep Packet Inspection (DPI)

The BPF Verifier enforces a strict instruction limit and forbids indeterminate loops. Implementing payload matching for signatures like "root" required:

- **Loop Unrolling:** Utilizing `#pragma unroll` to satisfy the verifier's requirement for bounded execution.
- **Pointer Arithmetic Validation:** Implementing rigorous bounds checking against `data_end` to prevent out-of-bounds memory access during L7 inspection.

### 2. Wire-Speed Performance vs. Complexity

Inspecting payloads often introduces latency. Hyperion solves this by:

- **Early Exit:** Dropping non-relevant traffic (e.g., non-TCP or specific ports) before the DPI engine is even invoked.
- **Zero-Copy Telemetry:** Using BPF Ring Buffers (introduced in Kernel 5.8) instead of Perf Buffers, reducing CPU overhead and memory fragmentation under high load (~976K events/sec).

### 3. Dynamic Policy Injection without Re-programming

To avoid detaching the XDP program and losing packets during updates:

- **BPF Maps:** Hyperion leverages BPF Maps to hot-reload signatures and blacklists. This allows `hyperion_ctrl` to update security policies in real-time without interrupting the packet processing pipeline.

### 4. The "Two Towers" Contextual Gap

A major challenge in systems security is that the Network Layer (XDP) doesn't know about Process IDs (PIDs).

- **Current Solution:** Hyperion focuses on the "Transport Boundary," while Sentinel monitors the "Process Boundary."
- **Future Work:** Exploring `task_struct` correlation via socket cookies to bridge this visibility gap.

---

## [ 0x05 ] DEMO ARTIFACT

**Live Verification:** The system drops a payload containing the signature "root" and then dynamically reloads to block "admin" without restarting.

[![asciicast](https://asciinema.org/a/ShlOWFRxuQABuwp4.svg)](https://asciinema.org/a/ShlOWFRxuQABuwp4)

---

## [ 0x06 ] OPERATIONAL MANUAL

### Prerequisites

* Linux Kernel 5.4+ (BTF Support)
* `clang`, `llvm`, `make`, `golang`

### Quick Start (vM5)

```bash
# 1. Compile the Engine
make

# 2. Configure Signatures
echo "root" > signatures.txt
echo "admin" >> signatures.txt

# 3. Attach to Interface (e.g., lo or wlp1s0)
sudo ./bin/hyperion_ctrl -iface wlp1s0

# 4. Enable Telemetry (Optional)
sudo ./bin/hyperion_ctrl -iface wlp1s0 -telemetry

# 5. Enable Telemetry with File Logging (Optional)
sudo ./bin/hyperion_ctrl -iface wlp1s0 -telemetry -logfile /var/log/hyperion.log

```

### Dynamic Reload (Zero Downtime)

Modify `signatures.txt` while the engine is running and trigger a hot-reload using `pkill`. The engine will update the BPF Map instantly.

```bash
# Update rules
echo "malware" >> signatures.txt

# Send Signal to Hyperion Controller
sudo pkill -HUP hyperion_ctrl

```

### Telemetry

See [docs/TELEMETRY.md](docs/TELEMETRY.md) for detailed information about:
- Event types and schema
- 5-tuple flow tracking
- CLI usage and options
- API reference for telemetry consumers

---

## [ 0x07 ] CITATION

```text
@software{hyperion2026,
  author = {Nevin},
  title = {Hyperion: High-Performance XDP Firewall},
  year = {2026},
  url = {[https://github.com/nevinshine/hyperion-xdp](https://github.com/nevinshine/hyperion-xdp)}
}

```

---

<div align="center">
<sub>Research Author: Nevin | Lab: Systems Security Research</sub>
</div>