# Hyperion XDP Telemetry (M5)

## Overview

The M5 milestone introduces comprehensive telemetry capabilities to Hyperion XDP via eBPF ring buffers and 5-tuple flow tracking. This allows real-time monitoring of packet decisions and flow statistics for security analysis and forensics.

---

## Event Types

Hyperion emits three types of telemetry events:

| Event Type | ID | Description |
|------------|-----|-------------|
| **ACCEPT** | 0 | Packet was allowed to pass through |
| **DROP** | 1 | Packet was dropped due to policy violation |
| **SIG_MATCH** | 2 | Packet matched a signature pattern |

---

## Event Schema

### Kernel Structure (`hyp_event`)

```c
struct hyp_event {
    __u8 event_type;    // 0=ACCEPT, 1=DROP, 2=SIG_MATCH
    __u8 _pad1[3];      // Padding for alignment
    __u32 src_ip;       // Source IP address (network byte order)
    __u32 dst_ip;       // Destination IP address (network byte order)
    __u16 src_port;     // Source port (network byte order)
    __u16 dst_port;     // Destination port (network byte order)
    __u8 protocol;      // IP protocol (6=TCP, 17=UDP)
    __u8 _pad2[7];      // Padding for 8-byte alignment before timestamp
    __u64 timestamp;    // Event timestamp (nanoseconds since epoch)
    char signature[8];  // Matched signature (if any)
};
```

**Total Size:** 40 bytes (with explicit padding for alignment)

### Go Structure (`HypEvent`)

```go
type HypEvent struct {
    EventType uint8    // 0=ACCEPT, 1=DROP, 2=SIG_MATCH
    _         [3]uint8 // Padding for alignment
    SrcIP     uint32
    DstIP     uint32
    SrcPort   uint16
    DstPort   uint16
    Protocol  uint8
    _         [7]uint8 // Padding for 8-byte alignment before Timestamp
    Timestamp uint64
    Signature [8]byte
}
```

**Total Size:** 40 bytes (matches C struct exactly)

---

## Flow Tracking

### 5-Tuple Flow Key

Hyperion tracks network flows using a 5-tuple hash key:

```c
struct flow_key {
    __u32 src_ip;       // Source IP address
    __u32 dst_ip;       // Destination IP address
    __u16 src_port;     // Source port
    __u16 dst_port;     // Destination port
    __u8 protocol;      // IP protocol
};
```

### Flow Statistics

For each flow, the following statistics are maintained:

```c
struct flow_value {
    __u64 packets;      // Total packets in this flow
    __u64 bytes;        // Total bytes in this flow
    __u64 first_seen;   // First packet timestamp (nanoseconds)
    __u64 last_seen;    // Last packet timestamp (nanoseconds)
};
```

The flow map uses `BPF_MAP_TYPE_LRU_HASH` with a maximum of 10,000 entries. When the limit is reached, the least recently used flows are automatically evicted.

---

## CLI Usage

### Basic Usage

Run Hyperion without telemetry (legacy alert mode only):

```bash
sudo ./bin/hyperion_ctrl -iface eth0
```

### Enable Telemetry

Enable real-time telemetry event output to stdout:

```bash
sudo ./bin/hyperion_ctrl -iface eth0 -telemetry
```

### Log to File

Enable telemetry and write events to a log file:

```bash
sudo ./bin/hyperion_ctrl -iface eth0 -telemetry -logfile /var/log/hyperion.log
```

### Load Signatures from CLI

Specify signatures directly via command line:

```bash
sudo ./bin/hyperion_ctrl -iface eth0 -telemetry -sig "malware,hack,evil"
```

### Complete Example

Run with all features enabled:

```bash
sudo ./bin/hyperion_ctrl -iface eth0 -telemetry -logfile /tmp/hyperion_events.log -sig "root,admin"
```

---

## Event Output Format

Telemetry events are formatted as follows:

```
[YYYY-MM-DD HH:MM:SS] EVENT_TYPE SRC_IP:SRC_PORT -> DST_IP:DST_PORT PROTOCOL sig="signature"
```

### Examples

**ACCEPT Event:**
```
[2026-02-01 12:34:56] ACCEPT 192.168.1.101:12345 -> 10.0.0.2:443 TCP
```

**DROP Event:**
```
[2026-02-01 12:34:56] DROP 192.168.1.100:54321 -> 10.0.0.1:80 TCP sig="malware"
```

**SIG_MATCH Event:**
```
[2026-02-01 12:34:57] SIG_MATCH 192.168.1.100:54321 -> 10.0.0.1:80 TCP sig="malware"
```

Note: `SIG_MATCH` events are emitted when a signature is detected, followed immediately by a `DROP` event if the packet is blocked.

---

## Color Coding

When output to a terminal, events are color-coded:

- **ACCEPT** - Green
- **DROP** - Red
- **SIG_MATCH** - Yellow

---

## Signal Handling

Hyperion supports the following signals:

| Signal | Action |
|--------|--------|
| `SIGINT` (Ctrl+C) | Graceful shutdown |
| `SIGTERM` | Graceful shutdown |
| `SIGHUP` | Reload signature policy without restart |

Example reload:

```bash
# Update signatures
echo "newmalware" > signatures.txt

# Trigger reload
sudo pkill -HUP hyperion_ctrl
```

---

## API Reference for Telemetry Consumers

### Ring Buffer Map

**Name:** `telemetry_ringbuf`  
**Type:** `BPF_MAP_TYPE_RINGBUF`  
**Size:** 64KB (65536 bytes)

### Flow Map

**Name:** `flow_map`  
**Type:** `BPF_MAP_TYPE_LRU_HASH`  
**Max Entries:** 10,000

### Reading Events in Go

```go
import (
    "github.com/cilium/ebpf/ringbuf"
)

// Create reader
reader, err := ringbuf.NewReader(objs.TelemetryRingbuf)
if err != nil {
    log.Fatal(err)
}
defer reader.Close()

// Read events
for {
    record, err := reader.Read()
    if err != nil {
        if err == ringbuf.ErrClosed {
            return
        }
        continue
    }
    
    var event HypEvent
    if err := binary.Read(bytes.NewReader(record.RawSample), 
                         binary.LittleEndian, &event); err != nil {
        log.Printf("Failed to parse event: %v", err)
        continue
    }
    
    // Process event...
}
```

---

## Performance Considerations

### Ring Buffer

- Events are written to a lock-free ring buffer in kernel space
- Non-blocking writes: if the buffer is full, events are dropped
- User space reads are blocking with configurable timeout

### Flow Tracking

- LRU eviction ensures memory usage stays bounded
- Atomic operations prevent race conditions
- Minimal overhead per packet (~100ns on modern CPUs)

### Telemetry Overhead

- When `-telemetry` is disabled: zero overhead (ring buffer is not read)
- When `-telemetry` is enabled: ~50-100ns per event for formatting and output
- File logging adds minimal I/O overhead (buffered writes)

---

## Troubleshooting

### No Events Appearing

1. Ensure `-telemetry` flag is set
2. Check that traffic is passing through the interface
3. Verify BPF program is attached: `sudo bpftool prog list`

### Ring Buffer Full

If events are being dropped, increase the ring buffer size in `hyperion_core.c`:

```c
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 17); // Increase from 1<<16 to 1<<17 (128KB)
} telemetry_ringbuf SEC(".maps");
```

### Flow Map Full

If flows are being evicted too frequently, increase the map size:

```c
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, struct flow_key);
    __type(value, struct flow_value);
    __uint(max_entries, 50000);  // Increase from 10000 to 50000
} flow_map SEC(".maps");
```

---

## Future Enhancements

- [ ] Query flow statistics via BPF map iteration
- [ ] Export metrics to Prometheus
- [ ] JSON output format option
- [ ] Filtering by event type
- [ ] Per-signature statistics dashboard

---

## License

Kernel Components (eBPF): GPLv2  
User Components (Go): MIT

---

## See Also

- [README.md](../README.md) - Main project documentation
- [MITRE_MAPPING.md](./MITRE_MAPPING.md) - MITRE ATT&CK mappings
