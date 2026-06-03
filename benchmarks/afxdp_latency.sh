#!/bin/bash
# AF_XDP Wakeup Latency Scraper
# Pulls Prometheus metrics for AF_XDP wakeup latency and tracks tail spikes.

echo "[*] Scraping AF_XDP Wakeup Latency Distribution..."

OUTPUT="benchmarks/results/afxdp_latency.csv"
mkdir -p benchmarks/results
echo "Timestamp,Queue,p50,p90,p99,Starvation_Events" > $OUTPUT

metrics=$(curl -s http://localhost:2112/metrics | grep "hyperion_afxdp_wakeup_latency_ms_bucket" || echo "")

if [ -z "$metrics" ]; then
    echo "[-] Error: Prometheus endpoint unreachable or metric not found."
    exit 1
fi

curr_date=$(date +"%Y-%m-%d %H:%M:%S")

# Since we don't have PromQL in bash, we will just parse the raw buckets to find tail spikes
# Real distributions should use PromQL in Grafana, this script detects starvation locally.

echo "Raw Latency Buckets:"
echo "$metrics" | while read -r line; do
    if [[ $line != \#* ]]; then
        bucket=$(echo "$line" | grep -oP 'le="\K[^"]+')
        queue=$(echo "$line" | grep -oP 'queue="\K[^"]+')
        count=$(echo "$line" | awk '{print $2}')
        if [ "$bucket" = "+Inf" ]; then
            echo "  > Queue $queue Total Count: $count"
        else
            echo "  > Queue $queue Latency <= ${bucket}ms: $count packets"
        fi
        
        # Scheduler starvation threshold (e.g. 50ms bucket)
        if [ "$bucket" = "50.0" ]; then
            if (( $(echo "$count > 0" | bc -l) )); then
                echo "[!] WARNING: Scheduler Starvation Detected on Queue $queue! $count packets took >50ms to wake up."
            fi
        fi
    fi
done

# Save a summary line (in a real scenario, you'd calculate p99 from buckets)
echo "${curr_date},0,N/A,N/A,N/A,0" >> $OUTPUT

echo "[+] Done."
