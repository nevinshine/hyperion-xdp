#!/bin/bash
# Hyperion XDP Benchmark Sandbox
# Sets up a veth pair to safely test XDP performance and AF_XDP queues

set -e

IF_ROOT="veth0"
IF_NS="veth1"
NS_NAME="hyp_test_ns"
IP_ROOT="10.0.0.1"
IP_NS="10.0.0.2"

if [ "$EUID" -ne 0 ]; then
  echo "Please run as root"
  exit 1
fi

echo "[*] Cleaning up old namespace..."
ip netns del $NS_NAME 2>/dev/null || true
ip link del $IF_ROOT 2>/dev/null || true

echo "[*] Creating network namespace: $NS_NAME"
ip netns add $NS_NAME

echo "[*] Creating veth pair ($IF_ROOT <--> $IF_NS)"
ip link add $IF_ROOT type veth peer name $IF_NS

echo "[*] Moving $IF_NS to $NS_NAME"
ip link set $IF_NS netns $NS_NAME

echo "[*] Configuring IPs"
ip addr add $IP_ROOT/24 dev $IF_ROOT
ip link set $IF_ROOT up

ip netns exec $NS_NAME ip addr add $IP_NS/24 dev $IF_NS
ip netns exec $NS_NAME ip link set $IF_NS up

# To allow traffic to flow, routing must be enabled
ip netns exec $NS_NAME ip route add default via $IP_ROOT

# Disable offloads on the veth interfaces to ensure XDP handles raw frames properly
ethtool -K $IF_ROOT tx off rx off tso off gso off gro off || true
ip netns exec $NS_NAME ethtool -K $IF_NS tx off rx off tso off gso off gro off || true

echo "[+] Sandbox Ready!"
echo "    Root IF: $IF_ROOT ($IP_ROOT)"
echo "    Test NS: $IF_NS ($IP_NS)"
echo ""
echo "To attach Hyperion: sudo ./bin/hyperion_ctrl -iface $IF_ROOT"
echo "To generate traffic: sudo ip netns exec $NS_NAME iperf3 -c $IP_ROOT -u -b 10G"
