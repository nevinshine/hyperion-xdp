# Local Testing Guide for Hyperion XDP M5

This guide provides step-by-step instructions for testing every component of the M5 telemetry implementation locally.

---

## Quick Start

### Option 1: Automated Testing (Recommended)

Run the comprehensive test script:

```bash
# Without sudo (skips runtime tests)
./test_all_local.sh

# With sudo (runs all tests including runtime)
sudo ./test_all_local.sh
```

This script tests all 8 sections automatically:
1. Environment prerequisites
2. Build & compilation
3. Unit tests
4. Struct alignment
5. CLI functionality
6. Runtime execution
7. Documentation
8. Integration tests

---

## Manual Testing by Section

### Section 1: Environment Check

Test your environment has all prerequisites:

```bash
# Check kernel version (need 5.4+)
uname -r

# Check required tools
which clang llvm gcc make go

# Check BPF support
cat /proc/sys/kernel/unprivileged_bpf_disabled

# Check Go version
go version
```

**Expected:** All tools installed, kernel 5.4+, Go 1.24+

---

### Section 2: Build & Compilation

Test that the project builds correctly:

```bash
# Clean previous builds
make clean

# Build the project
make build

# Verify binary exists
ls -lh bin/hyperion_ctrl

# Verify BPF objects generated
ls -lh src/user/bpf_bpfel.o
```

**Expected:** 
- Build completes without errors
- Binary `bin/hyperion_ctrl` exists (~5.2MB)
- BPF object files created in `src/user/`

---

### Section 3: Unit Tests

Run Go unit tests:

```bash
# Run all unit tests
cd src/user && go test -v

# Run specific test
go test -v -run TestHypEventStructSize

# Run benchmarks
go test -bench=. -benchmem

# Back to root
cd ../..
```

**Expected:** 8/8 tests pass, benchmark shows ~1025 ns/op

**Tests included:**
- `TestHypEventStructSize` - Struct is 40 bytes
- `TestFormatTelemetryEvent_Accept` - ACCEPT event formatting
- `TestFormatTelemetryEvent_Drop` - DROP event formatting
- `TestFormatTelemetryEvent_SigMatch` - SIG_MATCH event formatting
- `TestFormatTelemetryEvent_UDP` - UDP protocol detection
- `TestInt2IP` - IP address conversion
- `TestPortByteSwap` - Port byte order conversion
- `TestHypEventBinaryEncodeDecode` - Binary serialization

---

### Section 4: Struct Alignment

Verify C and Go structs match:

```bash
# Test Go struct size
cat > /tmp/test_go.go << 'EOF'
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
go run /tmp/test_go.go

# Test C struct size
cat > /tmp/test_c.c << 'EOF'
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
gcc /tmp/test_c.c -o /tmp/test_c && /tmp/test_c
```

**Expected:** Both output `40` (bytes)

---

### Section 5: CLI Functionality

Test command-line interface:

```bash
# Test help flag
./bin/hyperion_ctrl -h

# Verify all flags present
./bin/hyperion_ctrl -h | grep telemetry
./bin/hyperion_ctrl -h | grep logfile
./bin/hyperion_ctrl -h | grep sig
./bin/hyperion_ctrl -h | grep iface
```

**Expected:** Help shows all 4 flags with descriptions

**CLI Flags:**
- `-telemetry` - Enable telemetry event output
- `-logfile <path>` - Optional file for logging events
- `-sig <list>` - Comma-separated signatures
- `-iface <name>` - Interface to attach XDP (default: wlp1s0)

---

### Section 6: Runtime Tests (requires sudo)

Test actual program execution:

#### 6.1 Basic Execution
```bash
# Start without telemetry
sudo timeout 2 ./bin/hyperion_ctrl -iface lo
```
**Expected:** Shows banner, "Hyperion Active on lo", then timeout

#### 6.2 Telemetry Flag
```bash
# Start with telemetry enabled
sudo timeout 2 ./bin/hyperion_ctrl -iface lo -telemetry
```
**Expected:** Shows "Telemetry enabled" message

#### 6.3 File Logging
```bash
# Start with file logging
sudo timeout 2 ./bin/hyperion_ctrl -iface lo -telemetry -logfile /tmp/test.log

# Verify log file created
ls -lh /tmp/test.log
```
**Expected:** Log file `/tmp/test.log` created with root permissions

#### 6.4 CLI Signatures
```bash
# Load signatures from command line
sudo timeout 2 ./bin/hyperion_ctrl -iface lo -sig "test1,test2"
```
**Expected:** Shows "Loaded Rule 0: test1" and "Loaded Rule 1: test2"

#### 6.5 File-based Signatures
```bash
# Create signature file
echo "malware" > signatures.txt
echo "hack" >> signatures.txt

# Start Hyperion
sudo timeout 2 ./bin/hyperion_ctrl -iface lo
```
**Expected:** Shows "Loaded Rule 0: malware" and "Loaded Rule 1: hack"

#### 6.6 Signal Handling
```bash
# Start in background
sudo ./bin/hyperion_ctrl -iface lo &
PID=$!

# Send SIGHUP to reload
sudo kill -HUP $PID
sleep 1

# Send SIGTERM to stop
sudo kill -TERM $PID
```
**Expected:** SIGHUP triggers reload, SIGTERM causes graceful shutdown

---

### Section 7: Documentation

Verify all documentation exists:

```bash
# Check documentation files
ls -lh docs/TELEMETRY.md
ls -lh docs/TESTING.md
ls -lh docs/TEST_REPORT.md
ls -lh README.md

# Verify M5 is marked complete
grep "M5" README.md
```

**Expected:** All docs exist, M5 shows ✅ in README

---

### Section 8: Integration Tests

Run the full integration test suite:

```bash
# Run integration tests
./test_integration.sh
```

**Expected:** 10/10 tests pass

**Integration Tests:**
1. Binary compilation
2. Binary executable
3. Help flag
4. CLI flag recognition
5. Unit tests
6. Go struct size
7. C struct size
8. Documentation
9. Demo script
10. BPF compilation

---

## Testing Individual Components

### Test Event Formatting
```bash
cd src/user
go test -v -run TestFormatTelemetryEvent
cd ../..
```

### Test Struct Alignment
```bash
cd src/user
go test -v -run TestHypEventStructSize
cd ../..
```

### Test Binary Serialization
```bash
cd src/user
go test -v -run TestHypEventBinaryEncodeDecode
cd ../..
```

### Run Only Benchmarks
```bash
cd src/user
go test -bench=. -run=^$ -benchmem
cd ../..
```

---

## Common Issues & Solutions

### Issue: "Interface not found"
**Solution:** Check available interfaces:
```bash
ip link show
sudo ./bin/hyperion_ctrl -iface <your-interface>
```

### Issue: "Permission denied"
**Solution:** Run with sudo:
```bash
sudo ./bin/hyperion_ctrl -iface lo
```

### Issue: "BPF load failed"
**Solution:** Check kernel support:
```bash
uname -r  # Should be 5.4+
cat /proc/sys/kernel/unprivileged_bpf_disabled
```

### Issue: Build fails with "bpf_helpers.h not found"
**Solution:** Install libbpf development headers:
```bash
sudo apt-get install libbpf-dev
```

### Issue: "llvm-strip not found"
**Solution:** Install LLVM tools:
```bash
sudo apt-get install llvm
```

---

## Performance Testing

### Benchmark Event Formatting
```bash
cd src/user
go test -bench=BenchmarkFormatTelemetryEvent -benchtime=5s
cd ../..
```

### Test with Real Traffic
```bash
# Terminal 1: Start Hyperion with telemetry
sudo ./bin/hyperion_ctrl -iface lo -telemetry -logfile /tmp/hyperion.log

# Terminal 2: Generate traffic
curl http://localhost:8080/ &
ping -c 100 localhost

# Terminal 3: Monitor events
tail -f /tmp/hyperion.log
```

---

## Debugging

### Enable Verbose Output
```bash
# Run with Go race detector
cd src/user && go test -race -v
```

### Check BPF Maps
```bash
# List BPF programs
sudo bpftool prog list

# List BPF maps
sudo bpftool map list

# Dump a specific map
sudo bpftool map dump name policy_map
```

### View BPF Verifier Logs
```bash
# Enable verifier logs
echo 1 > /sys/kernel/debug/tracing/events/bpf/enable

# View logs
dmesg | tail -50
```

---

## CI/CD Integration

For automated testing in CI pipelines:

```bash
#!/bin/bash
# ci-test.sh

set -e

# Install dependencies
sudo apt-get update
sudo apt-get install -y clang llvm libbpf-dev

# Build
make clean
make build

# Run tests
cd src/user && go test -v
cd ../..

# Run integration tests
./test_integration.sh

echo "✅ All CI tests passed"
```

---

## Test Coverage Summary

| Component | Test Command | Expected Result |
|-----------|--------------|-----------------|
| Environment | `./test_all_local.sh` section 1 | All tools installed |
| Build | `make build` | Binary created |
| Unit Tests | `cd src/user && go test -v` | 8/8 pass |
| Benchmarks | `cd src/user && go test -bench=.` | ~1025 ns/op |
| Struct Size | Manual C/Go test | Both 40 bytes |
| CLI Flags | `./bin/hyperion_ctrl -h` | All 4 flags shown |
| Runtime | `sudo ./bin/hyperion_ctrl -iface lo` | Starts successfully |
| Documentation | `ls docs/*.md` | All files exist |
| Integration | `./test_integration.sh` | 10/10 pass |

---

## Need Help?

- **Full Test Report:** See `docs/TEST_REPORT.md`
- **Manual Testing:** See `docs/TESTING.md`
- **API Reference:** See `docs/TELEMETRY.md`
- **Demo Script:** Run `sudo ./demo_telemetry.sh`

---

## Quick Reference

```bash
# Run everything
sudo ./test_all_local.sh

# Just unit tests
cd src/user && go test -v

# Just integration tests
./test_integration.sh

# Start with telemetry
sudo ./bin/hyperion_ctrl -iface lo -telemetry

# Interactive demo
sudo ./demo_telemetry.sh
```
