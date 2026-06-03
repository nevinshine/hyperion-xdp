# Kernel Compatibility Matrix

This document defines the eBPF Verifier and AF_XDP compatibility contract across different Linux kernel epochs. The findings dictate how the Hyperion Dataplane degrades or behaves when deployed on older enterprise distributions versus bleeding-edge kernels.

## High-Level Compatibility Matrix

| Feature | Kernel 5.15 LTS (Ubuntu 22.04) | Kernel 6.1 LTS (Debian 12) | Kernel 6.6+ / 6.8 (Ubuntu 24.04) |
| :--- | :--- | :--- | :--- |
| **Generic XDP Fallback** | ✅ Supported | ✅ Supported | ✅ Supported |
| **Native AF_XDP Zero-Copy** | ✅ Supported (Driver Dependent) | ✅ Supported (Driver Dependent) | ✅ Supported (Driver Dependent) |
| **XDP Hardware Metadata kfuncs** | ❌ **REJECTED** by Verifier | ✅ Initial Support | ✅ Fully Stable |
| **CO-RE Relocations** | ✅ Stable | ✅ Stable | ✅ Stable |
| **Virtual Interface Redirect** | ❌ Silent Drop | ❌ Silent Drop | ❌ Silent Drop |

---

## Detailed Systems Knowledge & Quirks

### 1. eBPF Verifier Divergence: Hardware Metadata (`kfuncs`)

In the Hyperion codebase, we attempt to accelerate deep packet inspection by offloading RSS hash computation and timestamping to the physical NIC using `bpf_xdp_metadata_rx_hash` and `bpf_xdp_metadata_rx_timestamp`.

*   **Kernel 5.15**: These specific `kfuncs` do not exist. If the eBPF program attempts to load them, the kernel verifier will strictly **REJECT** the entire BPF object. This forces the userspace controller to catch the verifier error and dynamically fall back to the `hyperion_filter_generic` program, which strips out the metadata calls.
*   **Kernel 6.1+**: Hardware metadata `kfuncs` were merged in 6.1 (`net-next`). The verifier will successfully **ACCEPT** the program, but runtime execution depends on the specific NIC driver implementing the underlying `xdp_metadata_ops`. If the driver lacks support, the kernel gracefully returns an error code without dropping the packet.

### 2. Semantic Differences: Generic vs. Native Mode

The architectural failure we discovered on the loopback (`lo`) and `veth` interfaces perfectly highlights the difference between Generic and Native XDP execution contexts:

*   **Native Mode (`XDP_DRV_MODE`)**: Executes directly in the driver's RX ring buffer. When paired with an AF_XDP socket in `XDP_ZEROCOPY` mode, the packet is mapped directly to userspace memory via `bpf_redirect_map`. This is the only configuration that scales to 10M+ PPS.
*   **Generic Mode (`XDP_SKB_MODE`)**: Executes much later in the networking stack, operating on socket buffers (`sk_buff`). **CRITICAL QUIRK:** Across all tested kernel versions (5.15 through 6.8), the Linux kernel contains a routing limitation where `xdp_do_generic_redirect` silently fails to push packets into a `BPF_MAP_TYPE_XSKMAP` if the traffic originates from a virtual interface (`lo`, `veth`). The packet is dropped, and no error counter is incremented.

### 3. AF_XDP Socket Binding Shifts

*   **XDP_COPY Fallback**: If a system attempts to bind an AF_XDP socket to a virtual interface or a physical NIC without Zero-Copy driver support, `libbpf` and `asavie/xdp` will gracefully fall back to `XDP_COPY` mode.
*   **Fatal Misconfiguration**: If userspace forces the eBPF program into **Native Mode** (`XDP_DRV_MODE`), but the AF_XDP socket falls back to **SKB Mode** (`XDP_COPY`), the kernel will successfully execute the eBPF program, return `XDP_REDIRECT`, and then immediately drop the packet internally because the driver cannot perform an SKB-copy redirect. 

## Automated Validation Suite

To empirically validate these limits on future environments, an automated orchestration suite is provided at `tests/matrix_suite.sh`. It spins up isolated libvirt Vagrant VMs for Ubuntu 22.04, Debian 12, and Ubuntu 24.04, compiles the eBPF objects locally within the guest, and probes the verifier behavior using `internal_matrix_probe.sh`.
