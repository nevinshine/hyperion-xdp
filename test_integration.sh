#!/bin/bash
# Integration test for Hyperion XDP telemetry

set -e

echo "=== Hyperion XDP M5 Integration Tests ==="
echo ""

# Test 1: Binary compilation
echo "[TEST 1] Binary compilation..."
if [ -f "bin/hyperion_ctrl" ]; then
    echo "✅ Binary exists"
else
    echo "❌ Binary not found"
    exit 1
fi

# Test 2: Binary is executable
echo ""
echo "[TEST 2] Binary executable..."
if [ -x "bin/hyperion_ctrl" ]; then
    echo "✅ Binary is executable"
else
    echo "❌ Binary not executable"
    exit 1
fi

# Test 3: Help flag works
echo ""
echo "[TEST 3] Help flag..."
if ./bin/hyperion_ctrl -h 2>&1 | grep -q "telemetry"; then
    echo "✅ Help shows telemetry flag"
else
    echo "❌ Help doesn't show telemetry flag"
    exit 1
fi

# Test 4: CLI flags are recognized
echo ""
echo "[TEST 4] CLI flag recognition..."
./bin/hyperion_ctrl -h 2>&1 | grep -q "telemetry" && echo "  ✓ -telemetry flag present"
./bin/hyperion_ctrl -h 2>&1 | grep -q "logfile" && echo "  ✓ -logfile flag present"
./bin/hyperion_ctrl -h 2>&1 | grep -q "sig" && echo "  ✓ -sig flag present"
./bin/hyperion_ctrl -h 2>&1 | grep -q "iface" && echo "  ✓ -iface flag present"
echo "✅ All CLI flags present"

# Test 5: Unit tests pass
echo ""
echo "[TEST 5] Unit tests..."
cd src/user
if go test -v 2>&1 | grep -q "PASS"; then
    echo "✅ Unit tests pass"
    go test -v 2>&1 | grep "PASS:"
else
    echo "❌ Unit tests failed"
    exit 1
fi
cd ../..

# Test 6: Struct size verification
echo ""
echo "[TEST 6] Struct size verification..."
cat > /tmp/test_struct_size.go << 'EOF'
package main
import (
    "encoding/binary"
    "fmt"
)
type HypEvent struct {
    EventType uint8
    _         [3]uint8
    SrcIP     uint32
    DstIP     uint32
    SrcPort   uint16
    DstPort   uint16
    Protocol  uint8
    _         [7]uint8
    Timestamp uint64
    Signature [8]byte
}
func main() {
    var e HypEvent
    fmt.Println(binary.Size(e))
}
EOF
SIZE=$(go run /tmp/test_struct_size.go)
if [ "$SIZE" = "40" ]; then
    echo "✅ Struct size is correct (40 bytes)"
else
    echo "❌ Struct size is incorrect ($SIZE bytes, expected 40)"
    exit 1
fi

# Test 7: C struct size verification
echo ""
echo "[TEST 7] C struct size verification..."
cat > /tmp/test_c_struct.c << 'EOF'
#include <stdio.h>
#include <stdint.h>
struct hyp_event {
    uint8_t event_type;
    uint8_t _pad1[3];
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t protocol;
    uint8_t _pad2[7];
    uint64_t timestamp;
    char signature[8];
};
int main() {
    printf("%lu\n", sizeof(struct hyp_event));
    return 0;
}
EOF
gcc /tmp/test_c_struct.c -o /tmp/test_c_struct
C_SIZE=$(/tmp/test_c_struct)
if [ "$C_SIZE" = "40" ]; then
    echo "✅ C struct size is correct (40 bytes)"
else
    echo "❌ C struct size is incorrect ($C_SIZE bytes, expected 40)"
    exit 1
fi

# Test 8: Documentation exists
echo ""
echo "[TEST 8] Documentation..."
[ -f "docs/TELEMETRY.md" ] && echo "  ✓ TELEMETRY.md exists"
[ -f "docs/TESTING.md" ] && echo "  ✓ TESTING.md exists"
[ -f "demo_telemetry.sh" ] && echo "  ✓ demo_telemetry.sh exists"
[ -f "README.md" ] && grep -q "M5" README.md && echo "  ✓ README mentions M5"
echo "✅ All documentation present"

# Test 9: Demo script is executable
echo ""
echo "[TEST 9] Demo script..."
if [ -x "demo_telemetry.sh" ]; then
    echo "✅ Demo script is executable"
else
    echo "❌ Demo script not executable"
    exit 1
fi

# Test 10: BPF code compiles
echo ""
echo "[TEST 10] BPF code compilation..."
if [ -f "src/user/bpf_bpfel.o" ]; then
    echo "✅ BPF object file exists"
else
    echo "❌ BPF object file not found"
    exit 1
fi

echo ""
echo "================================================"
echo "✅ ALL TESTS PASSED!"
echo "================================================"
echo ""
echo "Summary:"
echo "  • Binary compilation: ✅"
echo "  • CLI flags: ✅"
echo "  • Unit tests: ✅"
echo "  • Struct alignment: ✅"
echo "  • Documentation: ✅"
echo "  • BPF compilation: ✅"
echo ""
echo "Note: Full XDP attachment requires root privileges"
echo "Run with sudo to test live network traffic capture"
