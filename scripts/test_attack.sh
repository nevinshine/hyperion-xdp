#!/usr/bin/env bash

set -euo pipefail

VICTIM_IP="10.0.0.2"
PORT=8080

echo "[*] Staging mock application service inside the Victim Environment..."
# Run a quick background netcat listener inside the victim space to catch raw text
ip netns exec victim nc -l -p $PORT > /tmp/victim_received.log 2>&1 &
NC_PID=$!

# Read eBPF trace_pipe in the background to catch low-level verifier/bpf_printk symbols
echo "[*] Attaching to kernel trace_pipe for eBPF debug symbols..."
cat /sys/kernel/tracing/trace_pipe > /tmp/hyperion_trace.log &
TRACE_PID=$!

# Ensure background jobs terminate when the script finishes
trap 'kill $NC_PID $TRACE_PID 2>/dev/null || true' EXIT

sleep 0.5

echo "[*] Sending standard icmp traffic from Attacker..."
if ip netns exec attacker ping -c 2 -W 1 $VICTIM_IP > /dev/null; then
    echo "[+] Standard ping succeeded."
else
    echo "[-] Ping dropped (Hyperion XDP may be filtering ICMP or link is broken)."
fi

echo -e "\n[*] Streaming malicious test signature from Attacker..."
# The eBPF signature matcher checks the FIRST 4 bytes of the payload.
# We must start the payload with the exact signature ('root') for it to match.
echo "root_shell_exploit_payload" | ip netns exec attacker nc -w 1 $VICTIM_IP $PORT || true

sleep 0.5

echo -e "\n[*] Kernel trace output during attack window:"
tail -n 15 /tmp/hyperion_trace.log || echo "No trace logs found."

echo -e "\n[*] Validation pass complete. Review your Go binary console logs to verify XDP verdicts."
