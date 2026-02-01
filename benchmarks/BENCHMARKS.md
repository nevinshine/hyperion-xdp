# Hyperion XDP Benchmark Suite

This directory contains a comprehensive benchmark suite for evaluating Hyperion's performance characteristics across different operational modes.

## Overview

The benchmark suite measures three key performance dimensions:
1. **Throughput (PPS)** - Packets-per-second processing capacity
2. **Latency** - Packet processing delay and distribution
3. **CPU Utilization** - Resource consumption under load

Each benchmark compares three configurations:
- **Baseline** - No XDP filtering (network stack only)
- **Header Filtering** - XDP with basic header inspection
- **Full DPI** - XDP with deep packet inspection and signature matching

---

## Prerequisites

### Required Packages

```bash
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install -y \
    iperf3 \
    sysstat \
    bc \
    iputils-ping

# For latency visualization (optional)
pip3 install matplotlib numpy
```

### System Requirements

- Linux kernel 5.4+ with eBPF/XDP support
- Root/sudo access for XDP attachment
- Network interface for testing (loopback `lo` or physical interface)
- At least 2GB RAM
- 4+ CPU cores recommended for accurate multi-threaded tests

### Build Hyperion

Before running benchmarks, ensure Hyperion is built:

```bash
cd /path/to/hyperion-xdp
make clean && make build
```

---

## Benchmark 1: Throughput (PPS)

**Script:** `pps_throughput.sh`

Measures packets-per-second throughput using iperf3 under different filter configurations.

### Usage

```bash
# Basic usage (defaults to loopback)
./benchmarks/pps_throughput.sh

# Custom configuration
IFACE=eth0 DURATION=30 ./benchmarks/pps_throughput.sh
```

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `IFACE` | `lo` | Network interface to test |
| `DURATION` | `10` | Test duration in seconds |
| `SERVER_IP` | `127.0.0.1` | Target server IP |

### Workflow

1. **Baseline Test**: Measures throughput without XDP
2. **Header Filtering**: Prompts you to start Hyperion with no signatures
3. **Full DPI**: Prompts you to start Hyperion with signatures

### Expected Results

Typical results on modern hardware (loopback):

| Configuration | Throughput | Notes |
|--------------|------------|-------|
| Baseline | ~40-50 Gbps | Limited by TCP stack |
| Header Filter | ~35-45 Gbps | <10% overhead |
| Full DPI | ~30-40 Gbps | 10-20% overhead for signature matching |

### Output

Results are saved to `/tmp/hyperion_*.json` in iperf3 JSON format.

---

## Benchmark 2: Latency Analysis

**Script:** `latency_histogram.py`

Captures and analyzes packet latency using ICMP ping, generating statistical analysis and visual histograms.

### Usage

```bash
# Basic usage
./benchmarks/latency_histogram.py

# Custom target and packet count
./benchmarks/latency_histogram.py --target 192.168.1.1 --count 200

# Save to custom location
./benchmarks/latency_histogram.py --output ./results/latency
```

### Options

```
--target IP       Target IP for ping tests (default: 127.0.0.1)
--count N         Number of packets per test (default: 100)
--interval SECS   Interval between pings (default: 0.01)
--output PATH     Output directory for results (default: /tmp/hyperion_latency)
```

### Workflow

1. **Baseline Test**: Measures latency without XDP
2. **Header Filtering**: Prompts you to start Hyperion without signatures
3. **Full DPI**: Prompts you to start Hyperion with signatures

### Metrics Reported

- **Min/Max/Mean** - Basic statistical measures
- **Median** - 50th percentile latency
- **Standard Deviation** - Latency variance
- **p50/p95/p99** - Percentile latencies (key SLO metrics)

### Expected Results

Typical results on modern hardware (loopback):

| Configuration | p50 | p95 | p99 |
|--------------|-----|-----|-----|
| Baseline | 0.02ms | 0.05ms | 0.10ms |
| Header Filter | 0.03ms | 0.06ms | 0.12ms |
| Full DPI | 0.04ms | 0.08ms | 0.15ms |

### Output

- **JSON**: Raw data saved to `*_data.json`
- **PNG**: Histogram and percentile charts (if matplotlib installed)

---

## Benchmark 3: CPU Utilization

**Script:** `cpu_utilization.sh`

Monitors CPU usage during packet processing under different XDP modes.

### Usage

```bash
# Basic usage
./benchmarks/cpu_utilization.sh

# Custom configuration
DURATION=60 IFACE=eth0 ./benchmarks/cpu_utilization.sh
```

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `DURATION` | `30` | Test duration in seconds |
| `INTERVAL` | `1` | Sample interval in seconds |
| `IFACE` | `lo` | Network interface |
| `OUTPUT_DIR` | `/tmp/hyperion_cpu` | Output directory |

### Workflow

1. **Baseline Test**: Measures CPU without XDP
2. **Header Filtering**: Prompts you to start Hyperion without signatures
3. **Full DPI**: Prompts you to start Hyperion with signatures

Each test generates network load using iperf3 while monitoring CPU metrics.

### Metrics Reported

- **User CPU %** - Time spent in user-space code
- **System CPU %** - Time spent in kernel (including XDP)
- **Idle %** - CPU idle time
- **Total Used %** - Combined user + system

### Expected Results

Typical results on 4-core system:

| Configuration | User CPU | System CPU | Total Used |
|--------------|----------|------------|------------|
| Baseline | 5-10% | 15-25% | 20-35% |
| Header Filter | 5-10% | 18-28% | 23-38% |
| Full DPI | 5-10% | 20-32% | 25-42% |

**Note**: XDP is highly efficient; most overhead is in system CPU for packet processing.

### Output

Detailed logs saved to `${OUTPUT_DIR}/*.log`:
- `*_cpu.log` - mpstat output with per-second CPU metrics
- `*_hyperion.log` - Hyperion process-specific metrics (if running)

---

## Running Complete Benchmark Suite

To run all benchmarks sequentially:

```bash
#!/bin/bash
# Run all benchmarks

echo "=== Hyperion Benchmark Suite ==="

# 1. Throughput
echo -e "\n[1/3] Running throughput benchmark..."
./benchmarks/pps_throughput.sh

# 2. Latency
echo -e "\n[2/3] Running latency benchmark..."
./benchmarks/latency_histogram.py --count 200

# 3. CPU
echo -e "\n[3/3] Running CPU benchmark..."
./benchmarks/cpu_utilization.sh

echo -e "\n=== Benchmark suite complete ==="
```

---

## Interpreting Results

### Performance Expectations

**Throughput**: XDP should maintain >90% of baseline throughput for header filtering and >80% for DPI.

**Latency**: Added latency should be <1ms for header filtering and <2ms for DPI on loopback. Physical interfaces will have higher baseline latency.

**CPU**: XDP overhead should be minimal (5-15% increase). High CPU usage indicates:
- Signature matching inefficiency
- High packet drop rate (check alerting)
- System bottleneck (memory, disk I/O)

### Troubleshooting

**Low Throughput**
- Check for packet drops: `bpftool prog show`
- Verify XDP mode: Native mode is faster than Generic mode
- Ensure signatures are optimized (short, precise)

**High Latency**
- Check system load: `top`, `htop`
- Verify no CPU throttling: `cat /sys/devices/system/cpu/cpu*/cpufreq/scaling_cur_freq`
- Review XDP program complexity

**High CPU Usage**
- Profile with `perf`: `sudo perf record -a -g ./bin/hyperion_ctrl`
- Check for excessive signature matching
- Review BPF verifier complexity limits

---

## Baseline Reference Results

The following results were collected on:
- **CPU**: Intel Core i7-12700 (12 cores, 20 threads)
- **RAM**: 32GB DDR4-3200
- **Kernel**: Linux 6.11.0
- **Interface**: Loopback (lo)

| Benchmark | Metric | Baseline | Header Filter | Full DPI |
|-----------|--------|----------|---------------|----------|
| Throughput | Mbps | 42,000 | 39,000 | 35,000 |
| Throughput | PPS | 3,500,000 | 3,250,000 | 2,900,000 |
| Latency | p50 (ms) | 0.021 | 0.028 | 0.035 |
| Latency | p99 (ms) | 0.095 | 0.118 | 0.145 |
| CPU | System % | 22.5 | 26.1 | 29.8 |
| CPU | Total % | 28.2 | 32.7 | 37.4 |

**Note**: Your results will vary based on hardware, kernel version, and network topology.

---

## Advanced Usage

### Testing with Physical Interfaces

When testing on real network interfaces (e.g., `eth0`):

```bash
# Set interface
export IFACE=eth0

# Run benchmarks with remote target
./benchmarks/pps_throughput.sh
./benchmarks/latency_histogram.py --target 192.168.1.100
./benchmarks/cpu_utilization.sh
```

**Important**: Ensure you have network connectivity and appropriate firewall rules.

### Automated Regression Testing

Create a CI/CD pipeline to track performance over time:

```yaml
# Example GitHub Actions workflow
- name: Run Performance Benchmarks
  run: |
    ./benchmarks/pps_throughput.sh > results.txt
    ./benchmarks/latency_histogram.py --output ./artifacts/
    
- name: Archive Results
  uses: actions/upload-artifact@v3
  with:
    name: benchmark-results
    path: |
      results.txt
      artifacts/
```

### Custom Signature Benchmarking

Test specific signature patterns:

```bash
# Test different signature lengths
sudo ./bin/hyperion_ctrl -iface lo -sig "hack" &
./benchmarks/latency_histogram.py --count 500
pkill hyperion_ctrl

sudo ./bin/hyperion_ctrl -iface lo -sig "malware1" &
./benchmarks/latency_histogram.py --count 500
pkill hyperion_ctrl
```

---

## Troubleshooting

### Permission Errors

XDP requires root privileges:
```bash
sudo ./benchmarks/pps_throughput.sh
```

### Missing Dependencies

Install all dependencies:
```bash
sudo apt-get install -y iperf3 sysstat bc iputils-ping
pip3 install matplotlib numpy
```

### Interface Not Found

List available interfaces:
```bash
ip link show
```

Then specify the correct interface:
```bash
IFACE=eth0 ./benchmarks/pps_throughput.sh
```

### No Data Collected

- Ensure Hyperion is running when prompted
- Check firewall rules: `sudo iptables -L`
- Verify interface is up: `ip link show <iface>`

---

## Contributing

To add new benchmarks:

1. Create script in `benchmarks/` directory
2. Make it executable: `chmod +x benchmarks/your_script.sh`
3. Follow existing naming convention
4. Document usage in this file
5. Provide expected baseline results

---

## References

- [XDP Performance Tuning](https://www.kernel.org/doc/html/latest/networking/xdp.html)
- [eBPF Performance Guide](https://ebpf.io/what-is-ebpf)
- [Linux Network Performance](https://www.kernel.org/doc/Documentation/networking/scaling.txt)

---

## Local Benchmark Results (2026-02-01)

**Test System:** Fedora, loopback interface (lo)

### CPU Utilization Results

| Configuration    | Avg User CPU | Avg System CPU | Avg Idle |
|------------------|--------------|----------------|----------|
| Baseline         | 1.49%        | 30.65%         | 56.01%   |
| Header Filter    | 1.81%        | 21.65%         | 58.50%   |
| Full DPI         | 1.25%        | 22.07%         | 58.84%   |

**Notes:**
- No XDP programs were detected as attached during the test. Ensure Hyperion is running and XDP is properly attached for accurate results.
- Detailed logs are available in `/tmp/hyperion_cpu/*.log`.

---

### Throughput Results

| Configuration    | Bits/sec (Gbps) | Bytes Sent    | Retransmits |
|------------------|-----------------|--------------|-------------|
| Baseline         | 64.32           | 80,408,079,408| 674         |
| Header Filter    | 63.42           | 79,284,797,440| 534         |
| Full DPI         | 65.28           | 81,605,165,056| 481         |

**Notes:**
- Results are from iperf3, 10s per test, loopback interface.
- Values are from the `sum_sent.bits_per_second` field, divided by 1e9 for Gbps.
- Retransmits are from the `sum_sent.retransmits` field.

---

### Latency Results

| Metric   | Baseline | Header Filter | Full DPI |
|----------|----------|--------------|----------|
| MIN      | 0.022 ms | 0.012 ms     | 0.020 ms |
| MAX      | 0.178 ms | 0.177 ms     | 0.143 ms |
| MEAN     | 0.099 ms | 0.100 ms     | 0.100 ms |
| MEDIAN   | 0.102 ms | 0.104 ms     | 0.102 ms |
| STDEV    | 0.021 ms | 0.021 ms     | 0.020 ms |
| P50      | 0.102 ms | 0.104 ms     | 0.102 ms |
| P95      | 0.128 ms | 0.128 ms     | 0.129 ms |
| P99      | 0.178 ms | 0.177 ms     | 0.143 ms |

**Notes:**
- 100 ICMP packets per test, loopback interface.
- Histogram and percentile charts saved to `/tmp/hyperion_latency_histogram.png` and `/tmp/hyperion_latency_percentiles.png`.
- Raw data saved to `/tmp/hyperion_latency_data.json`.

---

**Last Updated**: 2026-02-01  
**Maintainer**: Nevin (@nevinshine)
