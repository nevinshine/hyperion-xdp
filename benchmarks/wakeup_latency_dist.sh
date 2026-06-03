#!/bin/bash
# Wakeup Latency Distribution Scraper
# Pulls Prometheus metrics for AF_XDP wakeup latency

echo "[*] Scraping Wakeup Latency Distribution..."

metrics=$(curl -s http://localhost:2112/metrics | grep "hyperion_afxdp_wakeup_latency_ms_bucket" || echo "")

if [ -z "$metrics" ]; then
    echo "[-] Error: Prometheus endpoint unreachable or metric not found."
    echo "    Is hyperion_ctrl running?"
    exit 1
fi

echo "$metrics" | while read -r line; do
    if [[ $line != \#* ]]; then
        # Parse output: hyperion_afxdp_wakeup_latency_ms_bucket{le="0.1"} 100
        bucket=$(echo "$line" | grep -oP 'le="\K[^"]+')
        count=$(echo "$line" | awk '{print $2}')
        if [ "$bucket" = "+Inf" ]; then
            echo "  > Total Count: $count"
        else
            echo "  > Latency <= ${bucket}ms: $count packets"
        fi
    fi
done

echo "[+] Done."
