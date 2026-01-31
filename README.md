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
  > VERSION:       vM4.6 (Dynamic Policy + Ring Buffer)
  > ENGINE:        eBPF/XDP (Restricted C)
  > CONTROLLER:    Go (Cilium Library)
  > LICENSE:       GPLv2 (Kern) / MIT (User)
  > TARGET:        MSc Cybersecurity Research Artifact

```

---

## [ 0x01 ] ABSTRACT

**Hyperion** is a high-performance network security engine designed to enforce content-aware policy at the NIC driver level. Unlike traditional firewalls that operate at the socket layer (Netfilter), Hyperion uses **eBPF (Extended Berkeley Packet Filter)** and **XDP (Express Data Path)** to reject malicious payloads before the Linux Kernel allocates memory.

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
| **KERNEL ENFORCER** | Restricted C | **The Muscle.** Parses Layer 7 payloads in the driver. Implements bounded loops (32-byte window) for BPF safety. |
| **USER CONTROLLER** | Go (Cilium) | **The Brain.** Orchestrates BPF lifecycle. Handles `SIGHUP` for zero-downtime policy reloads. |
| **TELEMETRY** | Ring Buffer | **The Nerves.** Streams structured binary events from Kernel to User Space. |

---

## [ 0x03 ] CAPABILITY MILESTONES

We define success through distinct capability milestones.

| PHASE | GOAL | STATUS | OUTCOME |
| --- | --- | --- | --- |
| **M0** | Foundation | ✅ | `XDP_PASS` skeleton compiling with Clang/LLVM. |
| **M1** | Stateless Filtering | ✅ | Validated `XDP_DROP` against hardcoded IP targets. |
| **M2** | Stateful Tracking | ✅ | Volumetric flood detection via `BPF_MAP_TYPE_LRU_HASH`. |
| **M3** | Static DPI | ✅ | Layer 7 Payload Analysis scanning for signatures. |
| **M4** | Dynamic Policy | ✅ | **[STABLE]** Runtime updates via `BPF_MAP_TYPE_ARRAY` & CLI. |
| **M5** | Telemetry | 🔄 | **[CURRENT]** Ring Buffer active. Researching 5-tuple flow tracking. |

---

## [ 0x04 ] DEMO ARTIFACT

**Live Verification:** The system drops a payload containing the signature "root" while allowing normal traffic.

[Hyperion Demo](assets/hyperion_demo.gif)

---

## [ 0x05 ] OPERATIONAL MANUAL

### Prerequisites

* Linux Kernel 5.4+ (BTF Support)
* `clang`, `llvm`, `make`, `golang`

### Quick Start (vM4.6)

```bash
# 1. Compile the Engine
make

# 2. Configure Signatures
echo "root" > signatures.txt
echo "hack" >> signatures.txt

# 3. Attach to Interface (e.g., lo or wlp1s0)
sudo ./bin/hyperion_ctrl -iface lo

```

### Dynamic Reload

Modify `signatures.txt` while the engine is running and trigger a hot-reload:

```bash
# Find the PID printed on startup and send SIGHUP
sudo kill -HUP <PID>

```

---

## [ 0x06 ] CITATION

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
