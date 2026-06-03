#!/bin/bash
# Hyperion XDP Packet Drop Integration Test
# Verifies that packets to a blacklisted IP are successfully dropped.

set -e

IFACE="${1:-lo}"
TEST_IP="127.0.0.99"

echo "======================================"
echo " Hyperion XDP Drop Verification Test"
echo "======================================"

echo "1. Checking if Hyperion Controller is running..."
if ! pgrep -f "hyperion_ctrl" > /dev/null; then
    echo "Hyperion Controller is not running."
    echo "Please start it in another terminal: sudo ./bin/hyperion_ctrl -iface $IFACE"
    exit 1
fi

echo "2. Injecting malicious IP ($TEST_IP) into the blacklist..."
# Simulating the RPC call from Telos Domain Intelligence
curl -s -X POST "http://localhost:9095/block" -H "Content-Type: application/json" -d "{\"ip\": \"$TEST_IP\"}" > /dev/null
echo "IP successfully pushed to Hyperion XDP."

echo "3. Sending ICMP ping to the blacklisted IP..."
# We expect this to fail completely (100% packet loss)
ping -c 3 -W 1 $TEST_IP > /tmp/ping_output.txt || true

echo "4. Analyzing Results..."
if grep -q "100% packet loss" /tmp/ping_output.txt; then
    echo "✅ [PASS] Packets successfully dropped by XDP."
else
    echo "❌ [FAIL] Packets were NOT dropped. XDP enforcement failed."
    cat /tmp/ping_output.txt
    exit 1
fi

echo "Test completed successfully."
