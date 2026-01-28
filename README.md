# Project Hyperion: Datapath Security Research

**Hyperion** is a high-performance network security engine designed to enforce content-aware policy at the NIC driver level. Unlike traditional firewalls that operate at the socket layer (Netfilter), Hyperion uses **eBPF (Extended Berkeley Packet Filter)** and **XDP (Express Data Path)** to reject malicious payloads before the Linux Kernel allocates memory.

> **Research Context:** This project serves as the Network Satellite to the [Sentinel Runtime](https://github.com/nevinshine/sentinel-runtime) (Host Anchor). Authored by **Nevin**, it explores the unification of process-level and packet-level defense for the MSc Cybersecurity Research Portfolio.

---

## Research Motivation

Modern endpoint security focuses heavily on process-level control (syscalls). However, by the time a packet reaches a process, the kernel has already consumed significant resources parsing headers and managing buffers.

**The Research Question**

> *Can we inspect packet payloads for malicious signatures at wire speed (O(N)), dropping threats before the OS commits resources?*

### The "Two Towers" Architecture

Hyperion complements Sentinel by securing the transport boundary.

| Dimension | Sentinel (The Host) | Hyperion (The Wire) |
| --- | --- | --- |
| **Boundary** | Process Execution | Network Transport |
| **Mechanism** | `ptrace` / Kernel Modules | `eBPF` / `XDP` |
| **Visibility** | Syscalls (`execve`, `open`) | Payloads (`GET /hack HTTP/1.1`) |
| **Constraint** | Context-Aware Logic | Sub-microsecond Latency |
| **Threats** | Ransomware, Droppers | C2 Commands, Shellcode Injection |

---

## System Architecture

Hyperion operates on a split-plane design, utilizing the driver's interrupt context for maximum throughput. The vM4.6 architecture introduces dynamic policy maps and ring-buffer telemetry to decouple inspection from configuration.

```mermaid
graph TD
    A[Attacker] -->|Malicious Packet| B(Network Interface)
    B -->|XDP Hook| C{Hyperion Engine}
    
    %% Dynamic Policy Flow
    U[User Controller] -.->|Update Map| P[(Policy Map)]
    P -.->|Read Rule| C
    
    C -->|Parse L2-L4| D[Locate Payload]
    D -->|DPI Scan| E{Signature Match?}
    
    %% Decision Flow
    E -- Match --> F[XDP_DROP]
    E -- Clean --> G[XDP_PASS]
    
    %% Telemetry Flow
    F -.->|Push Event| R[(Ring Buffer)]
    R -.->|Poll & Decode| U
    U -->|ALERT LOG| L[Console Output]

```

### 1. Kernel Enforcer (`src/kern/`)

* **Technology:** Restricted C (eBPF).
* **Role:** Parses Layer 7 payloads directly in the driver.
* **Capabilities:** * **Dynamic Inspection:** Reads signatures from `BPF_MAP_TYPE_ARRAY` instead of hardcoded strings.
* **Telemetry:** Streams structured binary events via `BPF_MAP_TYPE_RINGBUF`.
* **Safety:** Implements bounded loops (32-byte window) to satisfy BPF verifier complexity limits.



### 2. User Space Controller (`src/user/`)

* **Technology:** Go (Cilium eBPF Library).
* **Role:** Orchestrates the BPF lifecycle.
* **Loader:** Injects policies from configuration files.
* **Monitor:** Asynchronously polls the ring buffer for alerts.
* **Manager:** Handles `SIGHUP` signals for zero-downtime updates.



---

## Version History & Roadmap

We define success through distinct capability milestones.

### [Phase M0] Foundation (Complete)

* **Goal:** Establish eBPF toolchain and verification pipeline.
* **Deliverable:** `XDP_PASS` skeleton compiling with Clang/LLVM.

### [Phase M1] Stateless Filtering (Complete)

* **Goal:** Implement high-performance dropping based on L3/L4 headers.
* **Research Validation:** Validated `XDP_DROP` against hardcoded IP targets.

### [Phase M2] Stateful Tracking (Complete)

* **Goal:** Implement stateful logic (Rate Limiting) in BPF Maps.
* **Outcome:** System successfully detected volumetric floods using `BPF_MAP_TYPE_LRU_HASH`.

### [Phase M3] Static DPI (Complete)

* **Goal:** Implement Layer 7 Payload Analysis in XDP.
* **Validation:** Custom logic scans TCP payloads for static signatures.
* **Outcome:** Malicious packets are dropped instantly; standard HTTP traffic passes.

### [Phase M4] Dynamic Policy (Stable Release)

* **Goal:** Decouple policy from code.
* **Outcome:** Implemented `BPF_MAP_TYPE_ARRAY` for runtime signature updates via CLI/Config.
* **Feature:** Zero-downtime reloads via `SIGHUP`.

### [Phase M5] Telemetry & Flow State (Current Research)

* **Goal:** Production observability and flow-aware context.
* **Status:** Ring Buffer telemetry active. Researching `LRU_HASH` for 5-tuple flow tracking to mitigate split-packet evasion.

### [Phase M6] Enterprise Integration (Future)

* **Goal:** Distributed policy synchronization and TLS-offload integration.

---

## Build & Run

### Prerequisites

* Linux Kernel 5.4+ (BTF Support)
* `clang`, `llvm`, `make`, `golang`

### Quick Start (vM4.6)

Hyperion uses a Go-based controller for reliable loading and visualization.

```bash
# 1. Compile the Engine
make

# 2. Configure Signatures
echo "root" > signatures.txt
echo "hack" >> signatures.txt

# 3. Attach to Interface (e.g., lo or wlp1s0)
sudo ./bin/hyperion_ctrl -iface lo

```

### Operational Guide

**Live Configuration Reload**
Modify `signatures.txt` while the engine is running and trigger a reload signal:

```bash
# Find the PID printed on startup
sudo kill -HUP <PID>
```

**Verification**
Attempt to send a malicious payload:

```bash
# This packet will be DROPPED by Hyperion
echo "root" | nc 127.0.0.1 8080
```
**Live Demo:**

![Hyperion Demo](assets/hyperion_demo.gif)

---

## License

This project is dual-licensed under the **GPLv2** (Kernel components) and **MIT** (User space components) to ensure compatibility with Linux kernel helper access and distribution norms.

---

**Author:** Nevin | **Lab:** Systems Security Research