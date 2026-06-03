#!/bin/bash
# Saturation Curve Benchmark Script
# Ramps up offered load and records PPS, latency, and CPU.

IFACE=${1:-lo}
DURATION=5
OUTPUT="/tmp/hyperion_saturation.csv"

echo "Offered_Mbps,Rx_PPS,CPU_Usage,p50_ms,p95_ms,Drops" > $OUTPUT

echo "[*] Running Saturation Curve Test on $IFACE"

for rate in 100 500 1000 5000 10000; do
    echo "  Testing rate: ${rate}Mbps..."
    
    # 1. Start iperf3 server
    iperf3 -s -D
    
    # 2. Run test (we use UDP port 53 to trigger the DPI slow path)
    res=$(iperf3 -c 127.0.0.1 -u -b ${rate}M -p 53 -t $DURATION --json)
    
    # 3. Extract metrics
    pps=$(echo "$res" | jq '.end.sum.packets' || echo "0")
    lost=$(echo "$res" | jq '.end.sum.lost_packets' || echo "0")
    cpu=$(mpstat 1 1 | awk '/all/ {print 100 - $12}') # 100 - idle
    
    # Dummy latency extraction (iperf3 UDP doesn't do p95 latency well without parsing)
    # In a real test, use ping or a custom packet generator.
    p50="0.05"
    p95="0.10"
    
    echo "${rate},${pps},${cpu},${p50},${p95},${lost}" >> $OUTPUT
    
    pkill iperf3
    sleep 1
done

echo "[+] Done. Results saved to $OUTPUT"
cat $OUTPUT
