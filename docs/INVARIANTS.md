# Hyperion Architectural Invariants

This document serves as the formal architectural contract for the Hyperion AF_XDP Dataplane. Any future modifications to the system must mathematically and operationally preserve these invariants to maintain the system's resilience and deterministic performance.

## 1. Queue Invariants

To eliminate lock contention and ensure deterministic, benchmarkable performance, the system enforces a strict **1:1:1:1 Execution Model**:

*   **1 RX Queue** ↔ **1 AF_XDP Socket** ↔ **1 Goroutine** ↔ **1 Pinned CPU Core**

**Rules:**
*   **No Worker Pools:** The system MUST NOT utilize dynamic Goroutine worker pools or channel-based work stealing for packet inspection.
*   **RSS Fan-out:** The eBPF Fast Path MUST redirect packets to the AF_XDP socket associated with the originating hardware RX Queue (`ctx->rx_queue_index`).
*   **Cache Locality:** Deep Packet Inspection (DPI) MUST occur within the L1/L2 cache of the CPU core pinned to the respective RX Queue.

## 2. Watchdog Invariants

The watchdog mechanism decouples temporal deadline enforcement (Kernel) from congestion backpressure management (Userspace).

**Rules:**
*   **Temporal Deadline:** The kernel eBPF program MUST independently read `bpf_ktime_get_ns()` and assert that the userspace heartbeat is no older than `STALL_THRESHOLD` (50ms).
*   **Strict State Machine:** The userspace controller MUST transition through states in a strict order: `HEALTHY` → `DEGRADED` → `RECOVERING` → `HEALTHY`.
*   **Hysteresis (Anti-Oscillation):** The system MUST NOT transition directly from `DEGRADED` to `HEALTHY`. It MUST enter `RECOVERING` and observe a minimum of 5 consecutive healthy evaluation ticks (50ms) before promoting to `HEALTHY`. This prevents eBPF routing flaps.

## 3. Fail-Open Semantics

Hyperion is an availability-oriented architecture. Forwarding continuity is always prioritized over strict security inspection.

**Rules:**
*   **Kernel Primacy:** The eBPF Fast Path MUST NOT drop traffic if the Slow Path fails.
*   **Socket Failure:** If the AF_XDP socket is unbound, uninitialized, or destroyed (e.g., via `SIGKILL`), the `bpf_redirect_map` lookup MUST fail gracefully and return `XDP_PASS`.
*   **Watchdog Starvation:** If the userspace controller freezes (e.g., via `SIGSTOP` or Garbage Collection pauses) and breaches the temporal deadline, the kernel MUST immediately return `XDP_PASS`.
*   **Congestion Shedding:** If the AF_XDP Rx ring buffer occupancy exceeds the safety threshold (> 50%), userspace MUST intentionally starve the heartbeat, forcing the kernel into `XDP_PASS`.

## 4. Telemetry Guarantees

Observability is a first-class citizen, but telemetry generation MUST NOT impact wire-speed forwarding or crash the kernel.

**Rules:**
*   **Lock-Free Fast Path:** All eBPF kernel drops MUST be recorded using `BPF_MAP_TYPE_PERCPU_ARRAY` to ensure atomic, lock-free counting across CPU cores.
*   **Bounded Ringbuf:** Metadata shipped to userspace MUST use `bpf_ringbuf_reserve`. If the ring buffer is saturated, the kernel MUST safely discard the telemetry event (`NULL` return handling) without dropping the packet.
*   **Transition Auditing:** Every watchdog state transition MUST emit a structured audit log containing: `Old State`, `New State`, `Reason`, and `Stall Duration` (on recovery).

## 5. Degradation Guarantees

When the system triggers Fail-Open semantics, it enters **Degraded Security Mode**.

**Rules:**
*   **Complete Bypass:** During degradation, AF_XDP Deep Packet Inspection is COMPLETELY bypassed. No partial inspections or queuing are permitted.
*   **L3 Fast Path Persists:** Even while degraded, `O(1)` LRU Blocklist map enforcement within the kernel MUST continue to drop explicitly blocked IP addresses. Only deep payload inspection is bypassed.
*   **Telemetry Indication:** Degradation MUST be explicitly visible via the `hyperion_watchdog_state = 1` Prometheus metric, ensuring infrastructure operators are aware that DPI guarantees are temporarily suspended.
