#!/bin/bash
# Hyperion AF_XDP Benchmark Suite
# Automates traffic generation and metric collection

NS_NAME="hyp_test_ns"
IP_ROOT="10.0.0.1"
DURATION=10

echo "Starting Hyperion AF_XDP Benchmark..."
echo "-----------------------------------"

# Check if sandbox is running
if ! ip netns list | grep -q "$NS_NAME"; then
    echo "[-] Error: Sandbox namespace '$NS_NAME' not found."
    echo "    Please run sudo ./scripts/netns_sandbox.sh first."
    exit 1
fi

if ! command -v iperf3 &> /dev/null; then
    echo "[-] Error: iperf3 is required. (sudo apt install iperf3)"
    exit 1
fi

echo "[*] Phase 1: Saturation Curve"
sudo ./benchmarks/saturation_curve.sh lo

echo "[*] Phase 2: Wakeup Latency Distribution"
sudo ./benchmarks/wakeup_latency_dist.sh > /tmp/hyperion_latency_dist.txt

echo "[*] Phase 3: Queue Scaling Validation"
sudo ./benchmarks/queue_scaling.sh

echo "[*] Phase 4: Full Throughput Blast (10s)"
echo "[*] Starting local iperf3 server..."
iperf3 -s -D

echo "[*] Blasting 10Gbps UDP traffic from namespace (Duration: ${DURATION}s)..."
# Target port 53 (DNS) to trigger the Slow Path AF_XDP redirect
echo "[*] Targeting Port 53 (AF_XDP Slow Path)"
iperf3_output=$(sudo ip netns exec $NS_NAME iperf3 -c $IP_ROOT -u -b 10G -p 53 -t $DURATION --json)

# Parse JSON output using jq (if available) or basic grep
if command -v jq &> /dev/null; then
    pps=$(echo "$iperf3_output" | jq '.end.sum.packets' || echo "N/A")
    lost=$(echo "$iperf3_output" | jq '.end.sum.lost_packets' || echo "N/A")
    bps=$(echo "$iperf3_output" | jq '.end.sum.bits_per_second' || echo "0")
    gbps=$(echo "scale=2; $bps / 1000000000" | bc 2>/dev/null || echo "N/A")
else
    echo "[-] Note: 'jq' not installed. Raw output saved to /tmp/hyperion_bench.json"
    echo "$iperf3_output" > /tmp/hyperion_bench.json
    pps="See JSON"
    lost="See JSON"
    gbps="See JSON"
fi

echo "[*] Fetching Prometheus Metrics..."
fast_drops=$(curl -s http://localhost:2112/metrics | grep "hyperion_fastpath_drops_total" | grep -v "#" | awk '{print $2}' || echo "0")
slow_drops=$(curl -s http://localhost:2112/metrics | grep "hyperion_slowpath_drops_total" | grep -v "#" | awk '{print $2}' || echo "0")
inspections=$(curl -s http://localhost:2112/metrics | grep "hyperion_slowpath_inspections_total" | grep -v "#" | awk '{print $2}' || echo "0")

echo "[*] Stopping iperf3 server..."
pkill iperf3

cat <<EOF > REPORT.md
# Hyperion AF_XDP Benchmark Report

**Configuration:**
- **Mode:** Zero-Copy AF_XDP Redirect (Slow Path)
- **Target Port:** UDP/53
- **Duration:** ${DURATION}s

## Traffic Metrics
| Metric | Value |
|--------|-------|
| Throughput | ${gbps} Gbps |
| Packets Sent | ${pps} |
| Packets Lost (iperf) | ${lost} |

## Dataplane Enforcement Metrics
| Metric | Value |
|--------|-------|
| Fast Path Drops (Kernel) | ${fast_drops} |
| AF_XDP Inspections (Go) | ${inspections} |
| AF_XDP Drops (Go) | ${slow_drops} |

## Architecture Notes
Traffic was generated in an isolated \`veth\` namespace and blasted at the root interface. The XDP hook parsed the L3/L4 headers. Since port 53 matched the \`redirect_ports\` policy, the packets were bypassed from the Linux networking stack and streamed directly into the Go userspace via AF_XDP rings for Deep Packet Inspection.

## Latency Distribution
\`\`\`
$(cat /tmp/hyperion_latency_dist.txt)
\`\`\`

## Advanced Data
Raw CSVs for graphing are available:
- \`/tmp/hyperion_saturation.csv\`
- \`/tmp/hyperion_queue_scaling.csv\`
EOF

echo ""
echo "[+] Benchmark Complete! Results saved to benchmarks/REPORT.md"
cat REPORT.md
