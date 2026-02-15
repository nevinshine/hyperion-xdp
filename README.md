# Hyperion XDP: Kernel-Space Defense Engine

**High-Performance Network Security Engine (eBPF/XDP)**

**Hyperion** is a high-performance network security engine designed to enforce content-aware policy at the Network Interface Card (NIC) driver level. Unlike traditional firewalls that operate at the socket layer (Netfilter/iptables), Hyperion uses **eBPF (Extended Berkeley Packet Filter)** and **XDP (Express Data Path)** to reject malicious payloads before the Linux Kernel allocates memory (`sk_buff`).

> [!NOTE]
> **Project Status: Active Research (M5.0)**
> * **Milestone:** Telemetry + Flow Tracking (Complete).
> * **Engine:** eBPF/XDP (Restricted C).
> * **Controller:** Go (Cilium Library).
> * **Target:** Cybersecurity Research Artifact.
> 
> 

## Abstract & Research Context

This project serves as the Network Satellite to the **[Sentinel Runtime](https://github.com/nevinshine/sentinel-runtime)** (Host Anchor). It explores the unification of process-level and packet-level defense.

> **The Research Question**
> *Can we inspect packet payloads for malicious signatures at wire speed (O(N)), dropping threats before the OS commits resources?*

## System Architecture

Hyperion operates on a split-plane design, utilizing the driver's interrupt context for maximum throughput.

### The "Two Towers" Defense

Hyperion complements Sentinel by securing the transport boundary.

| Dimension | Sentinel (The Host) | Hyperion (The Wire) |
| --- | --- | --- |
| **Boundary** | Process Execution | Network Transport |
| **Mechanism** | `ptrace` / Kernel Modules | `eBPF` / `XDP` |
| **Visibility** | Syscalls (`execve`, `open`) | Payloads (`GET /hack`) |
| **Constraint** | Context-Aware Logic | Sub-microsecond Latency |

### Component Logic

* **Kernel Enforcer (Restricted C):** The "Muscle." Parses Layer 7 payloads directly in the driver. Implements verifier-safe bounded loops for Deep Packet Inspection (DPI).
* **User Controller (Go/Cilium):** The "Brain." Orchestrates BPF lifecycle. Handles `SIGHUP` for zero-downtime policy reloads via BPF Maps.
* **Telemetry (Ring Buffer):** The "Nerves." Streams structured binary events from Kernel to User Space for forensic logging.

## Capability Milestones

We define success through distinct capability milestones.

| Phase | Goal | Status | Outcome |
| --- | --- | --- | --- |
| **M0** | Foundation | **[COMPLETE]** | `XDP_PASS` skeleton compiling with Clang/LLVM. |
| **M1** | Stateless Filtering | **[COMPLETE]** | Validated `XDP_DROP` against hardcoded IP targets. |
| **M2** | Stateful Tracking | **[COMPLETE]** | Volumetric flood detection via `BPF_MAP_TYPE_LRU_HASH`. |
| **M3** | Static DPI | **[COMPLETE]** | Layer 7 Payload Analysis scanning for signatures. |
| **M4** | Dynamic Policy | **[COMPLETE]** | Hot-swappable rules via `BPF_MAP_TYPE_ARRAY` & `SIGHUP`. |
| **M5** | Telemetry | **[COMPLETE]** | Ring Buffer telemetry with 5-tuple flow tracking. |

## Research & Engineering Challenges

> [!IMPORTANT]
> **Kernel Verifier Constraints**
> The eBPF verifier enforces strict safety guarantees, creating unique engineering challenges:
> * **Bounded Loops:** All loops must be provably terminating. Hyperion uses pragmatic bounds (512 iterations) for DPI scanning.
> * **Stack Limits:** The BPF stack is constrained to 512 bytes. Complex parsing requires careful memory planning.
> * **Helper Restrictions:** Only a subset of kernel helpers are available in XDP context (no socket access, no sleepable operations).
> 
> 

### Performance vs. Expressiveness

* **Deep Packet Inspection:** String matching at wire speed requires creative algorithms. Hyperion implements a verifier-safe Boyer-Moore-like approach.
* **Stateful Tracking:** LRU hash maps balance memory efficiency with high-cardinality flows.
* **Zero-Copy Telemetry:** Ring buffers provide lock-free event streaming without per-packet memcpy overhead.

### Integration Complexity

* **Hot Reload:** Updating BPF maps atomically while maintaining packet processing integrity.
* **Multi-Interface Support:** Managing lifecycle across diverse NIC drivers and modes (native vs. generic XDP).

## Operational Manual

### Prerequisites

* Linux Kernel 5.4+ (BTF Support)
* `clang`, `llvm`, `make`, `golang`

### Quick Start (vM5)

**1. Compile the Engine**

```bash
make

```

**2. Configure Signatures**
Define the payloads to block.

```bash
echo "root" > signatures.txt
echo "admin" >> signatures.txt

```

**3. Attach to Interface**
Attach the XDP program to your network interface (e.g., `eth0`, `wlp1s0`).

```bash
sudo ./bin/hyperion_ctrl -iface wlp1s0

```

**4. Enable Telemetry (Optional)**
Stream logs to a file for forensic analysis.

```bash
sudo ./bin/hyperion_ctrl -iface wlp1s0 -telemetry -logfile /var/log/hyperion.log

```

> [!TIP]
> **Dynamic Reload (Zero Downtime)**
> You can modify `signatures.txt` while the engine is running. Trigger a hot-reload using `SIGHUP` to update the BPF Map instantly without dropping packets.
> ```bash
> echo "malware" >> signatures.txt
> sudo pkill -HUP hyperion_ctrl
> 
> ```
> 
> 

## Citation

```bibtex
@software{hyperion2026,
  author = {Nevin Shine},
  title = {Hyperion: High-Performance XDP Firewall},
  year = {2026},
  url = {https://github.com/nevinshine/hyperion-xdp}
}

```

---

Nevin Shine (System Security Student) @ 2026
