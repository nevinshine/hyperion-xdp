# Hyperion XDP Testing Guide

## Overview

This document provides instructions for testing the Hyperion XDP telemetry and flow tracking features.

---

## Prerequisites

- Linux system with kernel 5.4+
- Root/sudo access
- Network interface for testing (e.g., `lo`, `eth0`, `wlp1s0`)
- `clang`, `llvm`, `make`, `golang` installed

---

## Building

```bash
# Clone the repository
git clone https://github.com/nevinshine/hyperion-xdp.git
cd hyperion-xdp

# Build the project
make

# Verify the binary was created
ls -lh bin/hyperion_ctrl
```

---

## Basic Testing

### Test 1: Start Without Telemetry (Legacy Mode)

```bash
# Start Hyperion on loopback interface
sudo ./bin/hyperion_ctrl -iface lo

# Expected output:
#     __  __                      _
#    / / / /_  ______  ___  _____(_)___  ____
#   / /_/ / / / / __ \/ _ \/ ___/ / __ \/ __ \
#  / __  / /_/ / /_/ /  __/ /  / / /_/ / / / /
# /_/ /_/\__, / .___/\___/_/  /_/\____/_/ /_/
#       /____/_/
#
#     :: Hyperion XDP Engine vM5 (Telemetry) ::
#
# [+] Hyperion Active on lo
# [i] PID: 12345 (Run 'kill -HUP 12345' to reload)
# ------------------------------------------------------------
# Waiting for threats...

# Press Ctrl+C to stop
```

### Test 2: Start With Telemetry Enabled

```bash
# Start with telemetry on loopback
sudo ./bin/hyperion_ctrl -iface lo -telemetry

# Generate some traffic in another terminal:
curl http://localhost:8080/ &

# Expected telemetry output:
# [2026-02-01 12:34:56] ACCEPT 127.0.0.1:54321 -> 127.0.0.1:8080 TCP
# [2026-02-01 12:34:56] ACCEPT 127.0.0.1:8080 -> 127.0.0.1:54321 TCP
```

### Test 3: Test With Signatures

```bash
# Create signatures file
echo "malware" > signatures.txt

# Start with telemetry
sudo ./bin/hyperion_ctrl -iface lo -telemetry -sig "hack,root"

# In another terminal, send malicious traffic:
echo "hack payload" | nc localhost 8080

# Expected output:
# [2026-02-01 12:35:00] SIG_MATCH 127.0.0.1:12345 -> 127.0.0.1:8080 TCP sig="hack"
# [2026-02-01 12:35:00] DROP 127.0.0.1:12345 -> 127.0.0.1:8080 TCP sig="hack"
# [15:35:00] ALERT: Blocked Traffic from 127.0.0.1 -> Payload: [hack pay]
```

### Test 4: Test File Logging

```bash
# Start with telemetry and file logging
sudo ./bin/hyperion_ctrl -iface lo -telemetry -logfile /tmp/hyperion.log

# Generate traffic
curl http://localhost:8080/ &

# Check the log file
tail -f /tmp/hyperion.log

# Expected log entries:
# [2026-02-01 12:36:00] ACCEPT 127.0.0.1:54322 -> 127.0.0.1:8080 TCP
# [2026-02-01 12:36:00] ACCEPT 127.0.0.1:8080 -> 127.0.0.1:54322 TCP
```

### Test 5: Test Dynamic Reload (SIGHUP)

```bash
# Start Hyperion
sudo ./bin/hyperion_ctrl -iface lo -telemetry &
HYPERION_PID=$!

# Update signatures
echo "evil" > signatures.txt

# Trigger reload
sudo kill -HUP $HYPERION_PID

# Expected output:
# [!] Reloading signatures...
#     -> Loaded Rule 0: evil
# [+] Reload Complete.

# Clean up
sudo kill -SIGTERM $HYPERION_PID
```

---

## Advanced Testing

### Flow Tracking Validation

The flow tracking feature maintains statistics for each 5-tuple flow. To validate:

1. Start Hyperion with telemetry
2. Generate multiple packets on the same connection
3. The flow map will track:
   - Packet count
   - Byte count
   - First seen timestamp
   - Last seen timestamp

Currently, flow statistics are maintained in kernel space but not directly exposed to user space. Future versions will add a query interface.

### BPF Map Inspection

You can inspect the BPF maps using `bpftool`:

```bash
# List all BPF programs
sudo bpftool prog list

# List all BPF maps
sudo bpftool map list

# Dump flow_map (requires map ID)
sudo bpftool map dump id <MAP_ID>

# Dump policy_map
sudo bpftool map dump name policy_map
```

---

## Performance Testing

### Throughput Test

Use `iperf3` to measure throughput with and without Hyperion:

```bash
# Terminal 1: Start iperf3 server
iperf3 -s

# Terminal 2: Baseline (without Hyperion)
iperf3 -c localhost -t 10

# Terminal 3: Start Hyperion
sudo ./bin/hyperion_ctrl -iface lo

# Terminal 2: Test with Hyperion
iperf3 -c localhost -t 10

# Compare throughput results
```

### Latency Test

Use `ping` to measure latency:

```bash
# Baseline
ping -c 100 localhost

# With Hyperion
sudo ./bin/hyperion_ctrl -iface lo &
ping -c 100 localhost
```

---

## Troubleshooting

### Issue: "Interface not found"

**Solution:** Check available interfaces and specify the correct one:

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

**Possible causes:**
1. Kernel too old (requires 5.4+)
2. BPF not enabled in kernel
3. Insufficient memory

**Check kernel version:**
```bash
uname -r
```

**Check BPF support:**
```bash
cat /proc/sys/kernel/unprivileged_bpf_disabled
```

### Issue: "No telemetry events appearing"

**Solution:**
1. Ensure `-telemetry` flag is set
2. Generate TCP traffic on the monitored interface
3. Check that the interface is receiving packets:
   ```bash
   sudo tcpdump -i lo -c 10
   ```

---

## Integration Testing

### Test with Real Network Traffic

```bash
# Monitor a real network interface
sudo ./bin/hyperion_ctrl -iface eth0 -telemetry -logfile /var/log/hyperion.log

# Generate HTTP traffic
curl http://example.com/

# Check telemetry output
tail -f /var/log/hyperion.log
```

### Test with Multiple Signatures

```bash
# Create comprehensive signature set
cat > signatures.txt << EOF
malware
hack
EOF

# Load and test
sudo ./bin/hyperion_ctrl -iface lo -telemetry

# Send test payloads
echo "This is malware" | nc localhost 8080
echo "This is hack attempt" | nc localhost 8080
echo "This is normal traffic" | nc localhost 8080
```

---

## Expected Behavior

### Event Types

1. **ACCEPT**: Displayed in green, indicates packet passed inspection
2. **DROP**: Displayed in red, indicates packet was blocked
3. **SIG_MATCH**: Displayed in yellow, indicates signature was matched (followed by DROP)

### Flow Tracking

- Each unique 5-tuple creates a new flow entry
- Flow statistics are updated atomically on each packet
- LRU eviction when 10,000 flows limit is reached
- Flow entries persist until evicted or program unload

### Graceful Shutdown

- SIGINT (Ctrl+C): Clean shutdown with map cleanup
- SIGTERM: Clean shutdown
- SIGHUP: Reload signatures without dropping packets

---

## Continuous Integration

For CI/CD pipelines, create automated tests:

```bash
#!/bin/bash
# test_hyperion.sh

set -e

# Build
make clean
make build

# Test help
./bin/hyperion_ctrl -h

# Test with mock interface (requires root)
# sudo timeout 5 ./bin/hyperion_ctrl -iface lo -telemetry &
# sleep 2
# curl http://localhost:8080/ || true
# wait

echo "All tests passed!"
```

---

## See Also

- [TELEMETRY.md](./TELEMETRY.md) - Telemetry documentation
- [README.md](../README.md) - Main project documentation
