#!/bin/bash
# Long Duration Soak Test Script
# Orchestrates 12h/24h/48h continuous traffic while recording memory growth and CPU drift.

HOURS=${1:-12}
IFACE=${2:-veth0}

OUTPUT="benchmarks/results/long_soak_${HOURS}h.csv"
mkdir -p benchmarks/results

if [ ! -f "$OUTPUT" ]; then
    echo "Timestamp,HoursElapsed,GoMemAllocMB,GoMemSysMB,CPUUsage,TotalDrops" > $OUTPUT
fi

echo "[*] Starting ${HOURS}h Long Soak Test on $IFACE..."
echo "    WARNING: This test will run for a very long time. Run inside tmux/screen."

pid=$(pgrep -f "hyperion_ctrl" || echo "")
if [ -z "$pid" ]; then
    echo "[-] Error: hyperion_ctrl must be running."
    exit 1
fi

duration_secs=$((HOURS * 3600))
start_time=$(date +%s)
end_time=$((start_time + duration_secs))

# Helper to get Go memory stats if pprof is enabled (assuming it is, or we use ps)
get_mem() {
    # Resident Set Size in MB
    ps -o rss= -p $pid | awk '{print $1/1024}'
}

# Start background traffic generator (mocked here)
# iperf3 -c ... -t $duration_secs &

while [ $(date +%s) -lt $end_time ]; do
    curr_date=$(date +"%Y-%m-%d %H:%M:%S")
    elapsed=$(( $(date +%s) - start_time ))
    hours_elapsed=$(echo "scale=2; $elapsed / 3600" | bc)
    
    mem_mb=$(get_mem || echo "0")
    cpu=$(mpstat 1 1 | awk '/all/ {print 100 - $12}')
    
    # Scrape total drops from prometheus
    drops=$(curl -s http://localhost:2112/metrics | grep "hyperion_fastpath_drops_total" | awk '{sum+=$2} END {print sum}' || echo "0")
    
    echo "${curr_date},${hours_elapsed},${mem_mb},N/A,${cpu},${drops}" >> $OUTPUT
    
    # Log every 10 minutes
    sleep 600
done

echo "[+] ${HOURS}h Soak Test Complete. Results saved to $OUTPUT"
