# Kernel Version Matrix Testing Strategy

Because eBPF verifier behavior and feature availability change across Linux kernel releases, testing against a single kernel is insufficient for production credibility.

## Current State (Phase 1)

Currently, the `ci.yml` pipeline tests the Hyperion XDP program against the default kernel provided by the GitHub Actions `ubuntu-latest` runner (typically a 6.x kernel).
It runs a `bpftool prog load` dry-run to ensure the verifier accepts the program and bounds checking passes.

## Roadmap (Phase 2)

We will introduce a QEMU-based kernel matrix test that boots minimal VMs to load and verify the eBPF object across different LTS kernels:

- **5.10 LTS** (Debian Bullseye, older enterprise environments)
- **5.15 LTS** (Ubuntu 22.04 LTS default)
- **6.1 LTS** (Debian Bookworm)
- **6.6 LTS** (Latest LTS, new eBPF features)

### Known Verifier Differences
- `bpf_loop()` helper is only available in 5.15+ (Hyperion avoids it to support 5.4+, but we may conditionally use it later).
- Ring buffer support (`BPF_MAP_TYPE_RINGBUF`) is available since 5.8 (Hyperion uses it, so 5.4 is unsupported without fallbacks).
- Bounded loops support was improved significantly in 5.3+.

### Implementation Plan
When self-hosted runners are available or GitHub Actions runner disk space is optimized, we will add a `strategy.matrix` to the CI workflow to boot these kernels using `qemu-system-x86_64` and execute the `verify_budget.sh` script via SSH/serial.
