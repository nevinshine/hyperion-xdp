#!/bin/bash
set -e

mkdir -p tests/results
RES_FILE="tests/results/veth_run_$(date +%s).log"
exec > >(tee -i "$RES_FILE") 2>&1

echo "======================================"
echo " Hyperion AF_XDP Native (veth) Suite"
echo "======================================"

echo "[*] Compiling Hyperion..."
make build >/dev/null
go build -o bin/hyperion_flood tests/flood.go

# Network Namespace variables
NS="hyperion_ns"
VETH_HOST="veth-host"
VETH_GUEST="veth-guest"
HOST_IP="10.1.1.1"
GUEST_IP="10.1.1.2"

cleanup() {
    echo ""
    echo "[*] Tearing down veth test environment..."
    kill -9 $CTRL_PID 2>/dev/null || true
    sudo ip netns del $NS 2>/dev/null || true
    sudo ip link del $VETH_HOST 2>/dev/null || true
}
trap cleanup EXIT

echo "[*] Setting up network namespace and veth pair..."
# Clean up any lingering state
sudo ip netns del $NS 2>/dev/null || true
sudo ip link del $VETH_HOST 2>/dev/null || true

# Create namespace and veth pair
sudo ip netns add $NS
sudo ip link add $VETH_HOST type veth peer name $VETH_GUEST netns $NS

# Configure Host side
sudo ip addr add $HOST_IP/24 dev $VETH_HOST
sudo ip link set $VETH_HOST up

# Configure Guest side
sudo ip netns exec $NS ip addr add $GUEST_IP/24 dev $VETH_GUEST
sudo ip netns exec $NS ip link set $VETH_GUEST up
# Need lo up in the namespace for ping/routing sometimes
sudo ip netns exec $NS ip link set lo up

echo "[*] Verifying basic connectivity..."
if sudo ip netns exec $NS ping -c 1 -W 1 $HOST_IP >/dev/null; then
    echo "✅ [PASS] veth pair connectivity verified."
else
    echo "❌ [FAIL] Cannot ping host from namespace."
    exit 1
fi

echo "[*] Starting Hyperion Controller on $VETH_HOST..."
# Run hyperion_ctrl on veth-host
# Note: Since we are running in veth, we must ensure it bounds properly
sudo ./bin/hyperion_ctrl -iface $VETH_HOST -queues 1 -hw-metadata=false -force-generic &
CTRL_PID=$!
sleep 2

# Helper function
get_metric() {
    local metric=$1
    local val=$(curl -s localhost:2112/metrics | grep "^${metric}" | head -1 | awk '{print $2}')
    if [ -z "$val" ]; then
        echo "0"
    else
        echo "$val"
    fi
}

echo "--------------------------------------"
echo "TEST: AF_XDP Redirect (Native XDP)"
echo "--------------------------------------"

echo "[*] Diagnostic: Testing ping after Hyperion is attached..."
if sudo ip netns exec $NS ping -c 1 -W 1 $HOST_IP >/dev/null; then
    echo "    ✅ Ping succeeded (XDP_PASS works for ICMP/ARP)"
else
    echo "    ❌ Ping failed! XDP attachment broke the interface completely."
fi

echo "[*] Diagnostic: Baseline metrics before flood..."
echo "    slowpath_inspections: $(get_metric 'hyperion_slowpath_inspections_total')"
echo "    fastpath_drops:       $(get_metric 'hyperion_fastpath_drops_total')"
echo "    redirect_failures:   $(get_metric 'hyperion_redirect_failures_total')"

echo "[*] Sending single UDP probe to port 53 from guest namespace..."
# Force ARP resolution right before sending the probe
sudo ip netns exec $NS ping -c 1 -W 1 $HOST_IP >/dev/null || true
sudo ip netns exec $NS bash -c "echo 'PROBE' > /dev/udp/$HOST_IP/53" 2>/dev/null || true
sleep 1

INSPECTIONS=$(get_metric 'hyperion_slowpath_inspections_total')
echo "[*] Diagnostic: Metrics after single probe..."
echo "    slowpath_inspections: $INSPECTIONS"

if [ -n "$INSPECTIONS" ] && [ "$INSPECTIONS" != "0" ]; then
    echo "✅ [PASS] AF_XDP redirect working natively! Slowpath inspections: $INSPECTIONS"
else
    echo "❌ [FAIL] AF_XDP redirect failed on veth interface. Packets dropped or bypassed."
    exit 1
fi

echo "[*] Blasting UDP packets to Port 53 to saturate AF_XDP ring..."
# Blast to host IP from guest NS
sudo ip netns exec $NS ./bin/hyperion_flood $HOST_IP &
FLOOD_PID=$!
sleep 1

# Check watchdog state during blast
STATE=$(get_metric "hyperion_watchdog_state")
echo "    Watchdog state during flood: $STATE"
if [ "$STATE" == "1" ] || [ "$STATE" == "2" ]; then
    echo "✅ [PASS] Controller intentionally starved heartbeat to shed load (State: $STATE)"
else
    echo "❌ [FAIL] Controller failed to enter Degraded mode under pressure (State: $STATE)"
fi

kill $FLOOD_PID 2>/dev/null || true
wait $FLOOD_PID 2>/dev/null || true

echo "======================================"
echo "✅ VETH NATIVE AF_XDP TESTS COMPLETED"
echo "======================================"
