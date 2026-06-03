#!/bin/bash
# Hyperion XDP Pktgen Benchmark
# Uses the Linux kernel pktgen module to blast UDP packets and measure XDP drop performance.

set -e

IFACE="${1:-lo}"
PKT_SIZE=64
COUNT=10000000

echo "======================================"
echo " Hyperion XDP Pktgen Drop Benchmark"
echo "======================================"
echo "Interface: $IFACE"
echo "Packet Size: $PKT_SIZE bytes"
echo "Count: $COUNT"

# Ensure pktgen module is loaded
sudo modprobe pktgen

# Setup pktgen for the specified interface
PGDEV="/proc/net/pktgen/$IFACE"

if [ ! -f "$PGDEV" ]; then
    echo "Adding $IFACE to pktgen thread 0"
    echo "add_device $IFACE" | sudo tee /proc/net/pktgen/kpktgend_0 > /dev/null
fi

echo "Configuring pktgen..."
echo "count $COUNT" | sudo tee "$PGDEV" > /dev/null
echo "clone_skb 1000" | sudo tee "$PGDEV" > /dev/null
echo "pkt_size $PKT_SIZE" | sudo tee "$PGDEV" > /dev/null
echo "dst 127.0.0.2" | sudo tee "$PGDEV" > /dev/null
echo "udp_dst_min 9000" | sudo tee "$PGDEV" > /dev/null
echo "udp_dst_max 9000" | sudo tee "$PGDEV" > /dev/null

echo "Running pktgen... (This will take a few moments)"
echo "start" | sudo tee /proc/net/pktgen/pgctrl > /dev/null

echo "Results:"
cat "$PGDEV" | grep "Result:"

echo "Benchmark complete."
