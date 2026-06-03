# Hyperion XDP Architecture

Hyperion XDP is a high-performance eBPF/AF_XDP enforcement and telemetry dataplane. It is designed around a strict separation of concerns to maximize packets-per-second (PPS) throughput while allowing deep payload inspection without violating eBPF verifier constraints.

## Fast Path vs. Slow Path Design

The system splits packet processing into two highly optimized domains:

### FAST PATH (Kernel/XDP)
The eBPF program attached to the NIC driver handles all incoming packets at the earliest possible point in the Linux networking stack.
**Responsibilities:**
- **Blocklisted IPs:** `O(1)` LRU Hash map lookups to drop known malicious IPs.
- **Malformed Packets:** Header length validation and bounds checking.
- **Stateless Filtering:** Dropping invalid protocols or malformed Ethernet frames.
- **Bounded Checks:** Strict, short, inline verifier-approved logic.
- **Routing:** Identifying target ports (e.g., UDP 53) that require Deep Packet Inspection and redirecting them to userspace using `bpf_redirect_map` (`BPF_MAP_TYPE_XSKMAP`).

### SLOW PATH (AF_XDP Userspace)
Packets redirected from the Fast Path bypass the standard Linux `sk_buff` allocation and are written directly into userspace memory via an AF_XDP Zero-Copy socket. The Go control plane polls this memory ring.
**Responsibilities:**
- **DNS Parsing:** Assembling and decoding complex Layer 7 payloads.
- **Deep Packet Inspection (DPI):** Scanning payloads against string signatures and regex rules defined in `policy.yaml`.
- **Telemetry Enrichment:** Correlating drops with Prometheus counters and shipping detailed metadata.
- **Policy Correlation:** Applying complex, stateful decisions that would be impossible or too expensive in the kernel.

---

## Explicit Verifier-Budget Discipline

To ensure the Fast Path remains provably safe and performant, Hyperion adheres to strict verifier discipline in `hyperion_core.c`:

1. **Bounded Loops:** All loops (e.g., DNS label parsing previously) have been removed from the kernel. Complex loop logic is deferred to the Go userspace, guaranteeing the eBPF instruction limit (1 million instructions) is never breached.
2. **Map Access Limits:** Lookups are kept minimal. We use an `O(1)` `LRU_HASH` for IP blocking to prevent Map Exhaustion (`E2BIG`). 
3. **Stack Constraints:** eBPF limits stack size to 512 bytes. We avoid allocating large temporary buffers or structures inside `hyperion_filter`. We write directly to the `telemetry_ringbuf` via `bpf_ringbuf_reserve`.
4. **Instruction Count Awareness:** By removing the `MAX_RULES` unrolled signature loop from the XDP program, we drastically reduced the compiled instruction count, ensuring lightning-fast load times and sub-microsecond latency.

## Queue Model Invariant

Hyperion strictly enforces a **1:1 Queue Model Invariant** for deterministic performance and benchmarkability:

**1 RX Queue ↔ 1 AF_XDP Socket ↔ 1 Goroutine ↔ 1 CPU Core**

This strict coupling ensures:
- **Zero Contention:** No locks are required when polling the AF_XDP UMEM rings.
- **Cache Locality:** Packet payloads remain in the L1/L2 cache of the pinned CPU core during deep packet inspection.
- **Measurability:** Performance degradation and saturation points can be modeled predictably.

We explicitly **reject** complex userspace abstractions that violate this invariant, including:
- Shared worker pools
- Dynamic goroutine migration
- Queue stealing
- Adaptive balancing

## Multi-Program Chaining (`libxdp`)

To achieve true production readiness and coexistence with infrastructure CNI plugins (e.g., Cilium) and load balancers (e.g., Katran), Hyperion supports `libxdp` multi-program dispatching.

Instead of acquiring an exclusive Netlink lock on the interface (which detaches existing XDP programs), Hyperion can be injected into the `libxdp` dispatcher sequence.

- **Run Priority:** Hyperion runs with priority `50` (early in the chain), ensuring malformed or malicious packets are dropped *before* they reach heavier load balancing or observability components.
- **Chain Call Actions:** Hyperion explicitly utilizes `XDP_PASS` (allowing the packet to proceed to the next program in the chain) and `XDP_DROP` (terminating the chain immediately).
- **Execution:** When the `-multiprog` flag is enabled, the Go controller dynamically shells out to `xdp-loader load` to attach the object and pins the memory maps to `/sys/fs/bpf/hyperion`. The controller then seamlessly reconnects to these pinned maps to manage policies and stream telemetry.

## CO-RE (Compile Once - Run Everywhere)

Hyperion strictly targets zero-trust enterprise environments. To achieve full portability without deploying compilation toolchains or kernel headers to production nodes, Hyperion uses a CO-RE architecture.

- **`vmlinux.h` Abstraction:** The kernel datapath (`hyperion_core.c`) abandons all host-specific `<linux/...>` headers. Instead, it relies on a monolithic `vmlinux.h` file containing BTF (BPF Type Format) definitions extracted directly from the kernel.
- **`bpf2go` Generation:** The `cilium/ebpf` library compiles the C code into a platform-agnostic ELF object embedded inside the Go binary.
- **Dynamic Relocation:** At runtime, the `cilium/ebpf` loader automatically reads the target production node's local BTF data (from `/sys/kernel/btf/vmlinux`) and patches the memory offsets of all kernel structures dynamically. This allows a single compiled binary to run seamlessly across heterogeneous kernel versions.

## Lock-Free Concurrency (Per-CPU Maps)

To completely eliminate spinlock contention on multi-queue NICs and high-core-count servers, Hyperion utilizes pure Lock-Free Concurrency for its primary state and telemetry.

- **`BPF_MAP_TYPE_PERCPU_ARRAY`**: Fast path drops are incremented completely lock-free. When a core evaluates a packet, it updates its local array segment without locking. The Go controller runs a low-frequency aggregation loop to read and sum the array segments across all CPUs into Prometheus metrics.
- **`BPF_MAP_TYPE_LRU_PERCPU_HASH`**: The IP Blocklist utilizes Per-CPU LRU hashing. This guarantees that eviction paths (under massive distributed IP attacks) do not cause cross-CPU cache-line bouncing.

## Architecture Diagram

```mermaid
graph TD
    A[NIC Rx Queue] --> B{XDP Hook<br>hyperion_core.c}
    B -- O(1) IP Blocklist --> C[XDP_DROP]
    B -- Unknown / Safe Port --> D[XDP_PASS<br>Linux Network Stack]
    B -- Target Port (e.g., 53) --> E[XDP_REDIRECT<br>xsk_map]
    
    E --> F[AF_XDP UMEM Ring]
    F --> G[Go Userspace<br>main.go Poll()]
    
    G -- Signature Match --> H[DPI Drop Metric]
    G -- Safe Payload --> I[Recycle Descriptor]
    
    J[(policy.yaml)] --> G
```
