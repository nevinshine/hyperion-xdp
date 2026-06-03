#!/bin/bash
# Hyperion XDP Attack Replay Script
# Blasts malicious traffic PCAPs into the AF_XDP Dataplane sandbox

NS_NAME="hyp_test_ns"
IF_NS="veth1"
PCAP_FILE=$1

echo "Hyperion Dataplane Attack Replay"
echo "--------------------------------"

if [ -z "$PCAP_FILE" ]; then
    echo "Usage: sudo ./scripts/attack_replay.sh <path_to_pcap>"
    echo "Example: sudo ./scripts/attack_replay.sh tests/pcaps/dns_flood.pcap"
    exit 1
fi

if ! command -v tcpreplay &> /dev/null; then
    echo "[-] Error: tcpreplay is not installed."
    echo "    Install using: sudo apt-get install tcpreplay"
    exit 1
fi

if ! ip netns list | grep -q "$NS_NAME"; then
    echo "[-] Error: Sandbox namespace '$NS_NAME' not found."
    echo "    Please run sudo ./scripts/netns_sandbox.sh first."
    exit 1
fi

echo "[*] Found PCAP: $PCAP_FILE"
echo "[*] Warning: Replaying traffic at maximum possible speed (--topspeed)"
echo "[*] Target Interface: $IF_NS (inside namespace $NS_NAME)"
echo "[*] Watch Prometheus metrics on :2112 for rx_queue_pressure and wakeup_latency!"

echo ""
echo "Starting tcpreplay..."
# Replay the PCAP inside the namespace, blasting it at top speed toward the root veth
sudo ip netns exec $NS_NAME tcpreplay --intf1=$IF_NS --topspeed $PCAP_FILE

echo ""
echo "[+] Attack Replay Complete!"
echo "Check /metrics for dropped frames and AF_XDP inspection counts."
