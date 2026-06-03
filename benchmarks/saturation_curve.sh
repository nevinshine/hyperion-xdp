#!/bin/bash
# Saturation Curve Benchmark Script
# Ramps up offered load and records PPS, latency, CPU, SoftIRQ, and Queue Occupancy.

IFACE=${1:-veth0}
DURATION=5
OUTPUT="benchmarks/results/saturation_curve.csv"

mkdir -p benchmarks/results
echo "Offered_Mbps,Rx_PPS,CPU_Usage,SoftIRQ,ksoftirqd_wakeups,Queue_Occupancy,p50_ms,p99_ms,Drops" > $OUTPUT

echo "[*] Running Saturation Curve Test on $IFACE"

# Function to get ksoftirqd wakeups
get_ksoftirqd() {
    ps -C ksoftirqd/0 -o min_flt= | tr -d ' ' || echo "0"
}

# Function to get softirq pressure for NET_RX
get_softirq() {
    cat /proc/softirqs | grep NET_RX | awk '{sum=0; for(i=2; i<=NF; i++) sum+=$i; print sum}'
}

for rate in 100 500 1000 5000 10000; do
    echo "  Testing rate: ${rate}Mbps..."
    
    softirq_start=$(get_softirq)
    ksoft_start=$(get_ksoftirqd)
    
    # 1. Start iperf3 server
    iperf3 -s -D
    
    # 2. Run test
    res=$(iperf3 -c 127.0.0.1 -u -b ${rate}M -p 53 -t $DURATION --json)
    
    # 3. Metrics extraction
    pps=$(echo "$res" | jq '.end.sum.packets' || echo "0")
    lost=$(echo "$res" | jq '.end.sum.lost_packets' || echo "0")
    cpu=$(mpstat 1 1 | awk '/all/ {print 100 - $12}') # 100 - idle
    
    softirq_end=$(get_softirq)
    ksoft_end=$(get_ksoftirqd)
    softirq_diff=$((softirq_end - softirq_start))
    ksoft_diff=$((ksoft_end - ksoft_start))
    
    # Attempt to get Queue Occupancy (Hardware specific, fallback to 0)
    q_occ=$(ethtool -S $IFACE 2>/dev/null | grep -i "rx_queue_0_bytes" | awk '{print $2}' || echo "0")
    
    # Scrape Prometheus for latency
    p50=$(curl -s http://localhost:2112/metrics | grep "hyperion_afxdp_wakeup_latency_ms" | grep "0.5" | head -n 1 | awk '{print $2}' || echo "0")
    p99=$(curl -s http://localhost:2112/metrics | grep "hyperion_afxdp_wakeup_latency_ms" | grep "50" | head -n 1 | awk '{print $2}' || echo "0")
    
    echo "${rate},${pps},${cpu},${softirq_diff},${ksoft_diff},${q_occ},${p50},${p99},${lost}" >> $OUTPUT
    
    pkill iperf3
    sleep 1
done

echo "[+] Done. Results saved to $OUTPUT"
cat $OUTPUT
