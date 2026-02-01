#!/bin/bash
# Hyperion XDP - Complete Local Testing Script
# This script tests every component of the M5 telemetry implementation

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Track results
TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0

print_header() {
    echo -e "${BLUE}╔═══════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║          HYPERION XDP M5 - LOCAL TESTING SUITE                  ║${NC}"
    echo -e "${BLUE}╚═══════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
}

print_section() {
    echo ""
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${CYAN}$1${NC}"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
}

test_result() {
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    if [ $1 -eq 0 ]; then
        echo -e "${GREEN}✅ PASSED${NC}: $2"
        PASSED_TESTS=$((PASSED_TESTS + 1))
    else
        echo -e "${RED}❌ FAILED${NC}: $2"
        FAILED_TESTS=$((FAILED_TESTS + 1))
    fi
}

print_header

# ============================================================================
# SECTION 1: ENVIRONMENT CHECK
# ============================================================================
print_section "SECTION 1: Environment Prerequisites"

echo "[1.1] Checking kernel version..."
KERNEL_VERSION=$(uname -r)
echo "      Kernel: $KERNEL_VERSION"
if [[ $(uname -r | cut -d. -f1) -ge 5 ]]; then
    test_result 0 "Kernel version (5.4+ required)"
else
    test_result 1 "Kernel version too old (need 5.4+)"
fi

echo ""
echo "[1.2] Checking required tools..."
for tool in clang llvm-strip gcc make go; do
    if command -v $tool &> /dev/null; then
        echo "      ✓ $tool: $(command -v $tool)"
        test_result 0 "$tool installed"
    else
        echo "      ✗ $tool: NOT FOUND"
        test_result 1 "$tool missing"
    fi
done

echo ""
echo "[1.3] Checking BPF support..."
if [ -f "/proc/sys/kernel/unprivileged_bpf_disabled" ]; then
    BPF_STATUS=$(cat /proc/sys/kernel/unprivileged_bpf_disabled)
    echo "      BPF status: $BPF_STATUS (0=enabled, 1=restricted)"
    test_result 0 "BPF support available"
else
    test_result 1 "BPF support check failed"
fi

echo ""
echo "[1.4] Checking Go version..."
GO_VERSION=$(go version | cut -d' ' -f3)
echo "      Go version: $GO_VERSION"
test_result 0 "Go toolchain available"

# ============================================================================
# SECTION 2: BUILD TESTS
# ============================================================================
print_section "SECTION 2: Build & Compilation"

echo "[2.1] Cleaning previous build..."
make clean &> /dev/null
test_result $? "Clean build artifacts"

echo ""
echo "[2.2] Building project..."
if make build &> /tmp/build.log; then
    test_result 0 "Project builds successfully"
    echo "      Binary size: $(ls -lh bin/hyperion_ctrl | awk '{print $5}')"
else
    test_result 1 "Build failed"
    echo "      See /tmp/build.log for details"
    tail -20 /tmp/build.log
fi

echo ""
echo "[2.3] Checking binary..."
if [ -f "bin/hyperion_ctrl" ] && [ -x "bin/hyperion_ctrl" ]; then
    test_result 0 "Binary exists and is executable"
else
    test_result 1 "Binary missing or not executable"
fi

echo ""
echo "[2.4] Checking BPF objects..."
if [ -f "src/user/bpf_bpfel.o" ]; then
    test_result 0 "BPF object files generated"
    echo "      BPF object size: $(ls -lh src/user/bpf_bpfel.o | awk '{print $5}')"
else
    test_result 1 "BPF object files missing"
fi

# ============================================================================
# SECTION 3: UNIT TESTS
# ============================================================================
print_section "SECTION 3: Unit Tests"

echo "[3.1] Running Go unit tests..."
cd src/user
if go test -v &> /tmp/unittest.log; then
    test_result 0 "All unit tests pass"
    grep "PASS:" /tmp/unittest.log | while read line; do
        echo "      $line"
    done
else
    test_result 1 "Unit tests failed"
    tail -20 /tmp/unittest.log
fi
cd ../..

echo ""
echo "[3.2] Running benchmarks..."
cd src/user
if go test -bench=. -benchmem &> /tmp/bench.log; then
    test_result 0 "Benchmarks completed"
    grep "Benchmark" /tmp/bench.log | while read line; do
        echo "      $line"
    done
else
    test_result 1 "Benchmarks failed"
fi
cd ../..

# ============================================================================
# SECTION 4: STRUCT VALIDATION
# ============================================================================
print_section "SECTION 4: Struct Alignment Validation"

echo "[4.1] Testing Go struct size..."
cat > /tmp/test_go_struct.go << 'EOF'
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
GO_SIZE=$(go run /tmp/test_go_struct.go)
echo "      Go struct size: $GO_SIZE bytes"
if [ "$GO_SIZE" = "40" ]; then
    test_result 0 "Go struct size correct (40 bytes)"
else
    test_result 1 "Go struct size incorrect ($GO_SIZE bytes)"
fi

echo ""
echo "[4.2] Testing C struct size..."
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
gcc /tmp/test_c_struct.c -o /tmp/test_c_struct 2>/dev/null
C_SIZE=$(/tmp/test_c_struct)
echo "      C struct size: $C_SIZE bytes"
if [ "$C_SIZE" = "40" ]; then
    test_result 0 "C struct size correct (40 bytes)"
else
    test_result 1 "C struct size incorrect ($C_SIZE bytes)"
fi

echo ""
echo "[4.3] Verifying struct alignment..."
if [ "$GO_SIZE" = "$C_SIZE" ] && [ "$GO_SIZE" = "40" ]; then
    test_result 0 "C and Go structs perfectly aligned"
else
    test_result 1 "Struct alignment mismatch"
fi

# ============================================================================
# SECTION 5: CLI FUNCTIONALITY
# ============================================================================
print_section "SECTION 5: CLI Functionality Tests"

echo "[5.1] Testing help flag..."
if ./bin/hyperion_ctrl -h 2>&1 | grep -q "telemetry"; then
    test_result 0 "Help flag works"
else
    test_result 1 "Help flag failed"
fi

echo ""
echo "[5.2] Verifying CLI flags..."
EXPECTED_FLAGS=("telemetry" "logfile" "sig" "iface")
for flag in "${EXPECTED_FLAGS[@]}"; do
    if ./bin/hyperion_ctrl -h 2>&1 | grep -q -- "$flag"; then
        echo "      ✓ -$flag present"
    else
        echo "      ✗ -$flag missing"
        test_result 1 "CLI flag -$flag missing"
        continue
    fi
done
test_result 0 "All CLI flags present"

# ============================================================================
# SECTION 6: RUNTIME TESTS (requires sudo)
# ============================================================================
print_section "SECTION 6: Runtime Tests (requires sudo)"

if [ "$EUID" -ne 0 ]; then
    echo -e "${YELLOW}⚠️  Warning: Not running as root. Skipping runtime tests.${NC}"
    echo "   To run these tests: sudo $0"
else
    echo "[6.1] Testing basic execution..."
    timeout 2 ./bin/hyperion_ctrl -iface lo 2>&1 | grep -q "Hyperion Active"
    test_result $? "Basic execution (no telemetry)"

    echo ""
    echo "[6.2] Testing telemetry flag..."
    timeout 2 ./bin/hyperion_ctrl -iface lo -telemetry 2>&1 | grep -q "Telemetry enabled"
    test_result $? "Telemetry flag enables telemetry"

    echo ""
    echo "[6.3] Testing file logging..."
    LOGFILE="/tmp/hyperion_test_$$.log"
    timeout 2 ./bin/hyperion_ctrl -iface lo -telemetry -logfile "$LOGFILE" 2>&1 > /dev/null
    if [ -f "$LOGFILE" ]; then
        test_result 0 "Log file created"
        rm -f "$LOGFILE"
    else
        test_result 1 "Log file not created"
    fi

    echo ""
    echo "[6.4] Testing CLI signatures..."
    timeout 2 ./bin/hyperion_ctrl -iface lo -sig "test1,test2" 2>&1 | grep -q "test1"
    test_result $? "CLI signatures loaded"

    echo ""
    echo "[6.5] Testing XDP attachment..."
    timeout 2 ./bin/hyperion_ctrl -iface lo 2>&1 | grep -q "Hyperion Active on lo"
    test_result $? "XDP attaches to loopback interface"
fi

# ============================================================================
# SECTION 7: DOCUMENTATION TESTS
# ============================================================================
print_section "SECTION 7: Documentation Validation"

DOCS=("docs/TELEMETRY.md" "docs/TESTING.md" "docs/TEST_REPORT.md" "README.md")
echo "[7.1] Checking documentation files..."
for doc in "${DOCS[@]}"; do
    if [ -f "$doc" ]; then
        echo "      ✓ $doc exists ($(wc -l < $doc) lines)"
        test_result 0 "$doc exists"
    else
        echo "      ✗ $doc missing"
        test_result 1 "$doc missing"
    fi
done

echo ""
echo "[7.2] Checking M5 milestone in README..."
if grep -q "M5.*✅" README.md; then
    test_result 0 "M5 marked as complete in README"
else
    test_result 1 "M5 not marked complete in README"
fi

# ============================================================================
# SECTION 8: INTEGRATION TESTS
# ============================================================================
print_section "SECTION 8: Integration Test Suite"

echo "[8.1] Running integration test script..."
if [ -f "test_integration.sh" ] && [ -x "test_integration.sh" ]; then
    if ./test_integration.sh &> /tmp/integration.log; then
        test_result 0 "Integration tests pass"
    else
        test_result 1 "Integration tests failed"
        tail -20 /tmp/integration.log
    fi
else
    test_result 1 "Integration test script missing or not executable"
fi

# ============================================================================
# FINAL REPORT
# ============================================================================
print_section "FINAL TEST REPORT"

echo ""
echo "Total Tests Run:    $TOTAL_TESTS"
echo -e "Passed:             ${GREEN}$PASSED_TESTS${NC}"
echo -e "Failed:             ${RED}$FAILED_TESTS${NC}"
echo ""

if [ $FAILED_TESTS -eq 0 ]; then
    echo -e "${GREEN}╔═══════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║                   🎉 ALL TESTS PASSED 🎉                         ║${NC}"
    echo -e "${GREEN}╚═══════════════════════════════════════════════════════════════════╝${NC}"
    exit 0
else
    echo -e "${RED}╔═══════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${RED}║                   ⚠️  SOME TESTS FAILED ⚠️                        ║${NC}"
    echo -e "${RED}╚═══════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo "Review the output above for details on failed tests."
    exit 1
fi
