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
  > MILESTONE:      M5.0 (Telemetry + Flow Tracking)
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

### Kernel Verifier Constraints

The eBPF verifier enforces strict safety guarantees, creating unique engineering challenges:

* **Bounded Loops:** All loops must be provably terminating. Hyperion uses pragmatic bounds (512 iterations) for DPI scanning.
* **Stack Limits:** The BPF stack is constrained to 512 bytes. Complex parsing requires careful memory planning.
* **Helper Function Restrictions:** Only a subset of kernel helpers are available in XDP context (no socket access, no sleepable operations).

### Performance vs. Expressiveness

* **Deep Packet Inspection:** String matching at wire speed requires creative algorithms. Hyperion implements a verifier-safe Boyer-Moore-like approach.
* **Stateful Tracking:** LRU hash maps balance memory efficiency with high-cardinality flows.
* **Zero-Copy Telemetry:** Ring buffers provide lock-free event streaming without per-packet memcpy overhead.

### Integration Complexity

* **Hot Reload:** Updating BPF maps atomically while maintaining packet processing integrity.
* **Multi-Interface Support:** Managing lifecycle across diverse NIC drivers and modes (native vs. generic XDP).
* **Telemetry Backpressure:** Handling scenarios where user space can't consume events fast enough.

---

## [ 0x05 ] DEMO ARTIFACT

**Live Verification:** The system drops a payload containing the signature "root" and then dynamically reloads to block "admin" without restarting.

[![asciicast](https://asciinema.org/a/dTObeTBqpOoSbzyD.svg)](https://asciinema.org/a/dTObeTBqpOoSbzyD)

---

## [ 0x05.1 ] BENCHMARK RESULTS

**See the latest local performance benchmarks:**

👉 [benchmarks/BENCHMARKS.md](benchmarks/BENCHMARKS.md)

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

See [docs/TELEMETRY.md](https://www.google.com/search?q=docs/TELEMETRY.md) for detailed information about:

* Event types and schema
* 5-tuple flow tracking
* CLI usage and options
* API reference for telemetry consumers

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
