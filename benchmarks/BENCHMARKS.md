# Hyperion XDP Engineering Benchmarks

This document establishes the empirical performance bounds of the Hyperion XDP Dataplane. It eschews generic "maximum PPS" claims in favor of rigorous engineering measurements: degradation curves, saturation limits, and hardware-specific scaling behaviors.

> [!WARNING]
> **Loopback vs. Physical NIC**: Most default test scripts bind to the loopback interface (`lo`) for convenience. Loopback results measure raw CPU instruction throughput but do not account for PCIe bus latency, NIC DMA ring sizes, or real-world IRQ coalescing. When publishing official numbers, tests **MUST** be run across two physical machines connected via 10G/40G/100G links.

---

## 1. Methodology & Hardware Context

Results are meaningless without exact context. Any benchmark submission must include the following matrix:

| Component | Value |
|-----------|-------|
| CPU Architecture | (e.g., Intel Xeon Platinum 8380, AMD EPYC 7763) |
| Core Count / NUMA | (e.g., 40 Cores / 2 Sockets) |
| Kernel Version | (e.g., 6.1.60 LTS) |
| NIC Driver | (e.g., `ixgbe`, `i40e`, `mlx5_core`) |
| AF_XDP Mode | Zero-Copy (Native) or Copy (Generic)? |
| eBPF Program Type | Native XDP (not SKB mode) |

**Tuning Applied:**
- IRQ Affinity: Pinned or round-robin?
- CPU Scaling Governor: `performance`
- Hyperthreading: Enabled/Disabled

---

## 2. Benchmark Categories & Scripts

The suite is divided into specific metrics designed to measure the 1:1 Queue Model under various stressors.

### A. Degradation Curves & Saturation Points
**Script:** `saturation_curve.sh`

Measures how performance gracefully degrades as offered load approaches and exceeds the single-core CPU capacity.

*Expected Output Format:*
| Offered Load | Actual Rx PPS | Drops (Kern) | Drops (Go) | CPU % (Core 0) | p95 Latency |
|--------------|---------------|--------------|------------|----------------|-------------|
| 1 Mpps | 1 Mpps | 0 | 0 | 12% | 0.05ms |
| 5 Mpps | 5 Mpps | 0 | 0 | 45% | 0.08ms |
| 10 Mpps | 9.2 Mpps | 0.8 Mpps | 0 | 100% | 0.45ms (Saturation) |

**Userspace Collapse Behavior:** When the AF_XDP ring fills faster than Go can dequeue it (Rx ring full), the kernel explicitly drops the packets. This is tracked by `hyperion_afxdp_rx_dropped_total`. The system does NOT fail-open in this scenario.

### B. Redirect Failure Thresholds
When traffic hits the target port (e.g., UDP 53), the kernel attempts `bpf_redirect_map`. If the socket is unbound or dead, it falls back to `XDP_PASS` (Fail-Open). We track exactly what PPS rate triggers mapping failures.

### C. Wakeup Latency Distributions
**Script:** `wakeup_latency_dist.sh`

Latency is tracked as the delta between the AF_XDP `Poll()` unblocking and the packet being dequeued. This is exposed via the Prometheus histogram `hyperion_afxdp_wakeup_latency_ms`.

*Sample Distribution (10 Mpps Load):*
- **< 0.1ms:** 85%
- **< 0.5ms:** 12%
- **< 1.0ms:** 2.9%
- **< 5.0ms:** 0.1% (GC Pauses)

### D. CPU & Queue Scaling
**Script:** `queue_scaling.sh`

Validates the linear scalability of the 1:1 invariant.
- 1 Queue / 1 Core: X Mpps
- 2 Queues / 2 Cores: ~1.95X Mpps
- 4 Queues / 4 Cores: ~3.8X Mpps

---

## 3. Running the Suite

Ensure you have a dedicated namespace or physical peer configured.

```bash
# 1. Run the saturation curve test
sudo ./benchmarks/saturation_curve.sh -i eth1 -target 10.0.0.2

# 2. Extract latency distribution
sudo ./benchmarks/wakeup_latency_dist.sh

# 3. Queue scaling validation
sudo ./benchmarks/queue_scaling.sh
```

All results are exported as CSVs to `/tmp/hyperion_benchmarks/` for easy graphing.

---

## 4. Current Official Baselines

*Pending formal physical NIC testing. See previous loopback tests for development baselines.*
