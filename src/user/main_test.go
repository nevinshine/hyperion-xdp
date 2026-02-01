package main

import (
	"bytes"
	"encoding/binary"
	"testing"
	"time"
)

// Test struct size and alignment
func TestHypEventStructSize(t *testing.T) {
	var event HypEvent
	size := binary.Size(event)
	expected := 40
	
	if size != expected {
		t.Errorf("HypEvent struct size = %d, want %d", size, expected)
	}
}

// Test event formatting for ACCEPT events
func TestFormatTelemetryEvent_Accept(t *testing.T) {
	event := &HypEvent{
		EventType: 0, // ACCEPT
		SrcIP:     0x0100007f, // 127.0.0.1 in little endian
		DstIP:     0x0100007f,
		SrcPort:   0x5000, // Port 80 in network byte order
		DstPort:   0xbb01, // Port 443 in network byte order
		Protocol:  6, // TCP
		Timestamp: uint64(time.Now().UnixNano()),
	}
	
	result := formatTelemetryEvent(event)
	
	// Check that result contains expected components
	if !bytes.Contains([]byte(result), []byte("ACCEPT")) {
		t.Errorf("Expected result to contain 'ACCEPT', got: %s", result)
	}
	if !bytes.Contains([]byte(result), []byte("TCP")) {
		t.Errorf("Expected result to contain 'TCP', got: %s", result)
	}
}

// Test event formatting for DROP events with signature
func TestFormatTelemetryEvent_Drop(t *testing.T) {
	event := &HypEvent{
		EventType: 1, // DROP
		SrcIP:     0x0100007f,
		DstIP:     0x0100007f,
		SrcPort:   0x5000,
		DstPort:   0xbb01,
		Protocol:  6,
		Timestamp: uint64(time.Now().UnixNano()),
	}
	copy(event.Signature[:], []byte("malware"))
	
	result := formatTelemetryEvent(event)
	
	if !bytes.Contains([]byte(result), []byte("DROP")) {
		t.Errorf("Expected result to contain 'DROP', got: %s", result)
	}
	if !bytes.Contains([]byte(result), []byte("malware")) {
		t.Errorf("Expected result to contain 'malware', got: %s", result)
	}
}

// Test event formatting for SIG_MATCH events
func TestFormatTelemetryEvent_SigMatch(t *testing.T) {
	event := &HypEvent{
		EventType: 2, // SIG_MATCH
		SrcIP:     0x0100007f,
		DstIP:     0x0100007f,
		SrcPort:   0x5000,
		DstPort:   0xbb01,
		Protocol:  6,
		Timestamp: uint64(time.Now().UnixNano()),
	}
	copy(event.Signature[:], []byte("hack"))
	
	result := formatTelemetryEvent(event)
	
	if !bytes.Contains([]byte(result), []byte("SIG_MATCH")) {
		t.Errorf("Expected result to contain 'SIG_MATCH', got: %s", result)
	}
	if !bytes.Contains([]byte(result), []byte("hack")) {
		t.Errorf("Expected result to contain 'hack', got: %s", result)
	}
}

// Test UDP protocol detection
func TestFormatTelemetryEvent_UDP(t *testing.T) {
	event := &HypEvent{
		EventType: 0,
		SrcIP:     0x0100007f,
		DstIP:     0x0100007f,
		SrcPort:   0x5000,
		DstPort:   0xbb01,
		Protocol:  17, // UDP
		Timestamp: uint64(time.Now().UnixNano()),
	}
	
	result := formatTelemetryEvent(event)
	
	if !bytes.Contains([]byte(result), []byte("UDP")) {
		t.Errorf("Expected result to contain 'UDP', got: %s", result)
	}
}

// Test IP address conversion
func TestInt2IP(t *testing.T) {
	tests := []struct {
		input    uint32
		expected string
	}{
		{0x0100007f, "127.0.0.1"},
		{0x0a000001, "1.0.0.10"},
		{0xc0a80001, "1.0.168.192"},
	}
	
	for _, tt := range tests {
		result := int2ip(tt.input)
		if result.String() != tt.expected {
			t.Errorf("int2ip(%x) = %s, want %s", tt.input, result, tt.expected)
		}
	}
}

// Test port byte order conversion
func TestPortByteSwap(t *testing.T) {
	tests := []struct {
		input    uint16
		expected uint16
	}{
		{0x5000, 0x0050}, // 80 in network byte order -> 80 in host byte order
		{0xbb01, 0x01bb}, // 443 in network byte order -> 443 in host byte order
		{0x5c11, 0x115c}, // 4444 in network byte order -> 4444 in host byte order
	}
	
	for _, tt := range tests {
		result := (tt.input >> 8) | (tt.input << 8)
		if result != tt.expected {
			t.Errorf("Port swap(%x) = %x, want %x", tt.input, result, tt.expected)
		}
	}
}

// Test binary encoding and decoding of HypEvent
func TestHypEventBinaryEncodeDecode(t *testing.T) {
	original := HypEvent{
		EventType: 1,
		SrcIP:     0x0100007f,
		DstIP:     0x0100007f,
		SrcPort:   0x5000,
		DstPort:   0xbb01,
		Protocol:  6,
		Timestamp: uint64(time.Now().UnixNano()),
	}
	copy(original.Signature[:], []byte("test"))
	
	// Encode
	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.LittleEndian, original)
	if err != nil {
		t.Fatalf("Failed to encode: %v", err)
	}
	
	// Verify size
	if buf.Len() != 40 {
		t.Errorf("Encoded size = %d, want 40", buf.Len())
	}
	
	// Decode
	var decoded HypEvent
	err = binary.Read(buf, binary.LittleEndian, &decoded)
	if err != nil {
		t.Fatalf("Failed to decode: %v", err)
	}
	
	// Compare
	if decoded.EventType != original.EventType {
		t.Errorf("EventType = %d, want %d", decoded.EventType, original.EventType)
	}
	if decoded.SrcIP != original.SrcIP {
		t.Errorf("SrcIP = %x, want %x", decoded.SrcIP, original.SrcIP)
	}
	if decoded.Protocol != original.Protocol {
		t.Errorf("Protocol = %d, want %d", decoded.Protocol, original.Protocol)
	}
	if decoded.Timestamp != original.Timestamp {
		t.Errorf("Timestamp = %d, want %d", decoded.Timestamp, original.Timestamp)
	}
}

// Benchmark event formatting
func BenchmarkFormatTelemetryEvent(b *testing.B) {
	event := &HypEvent{
		EventType: 1,
		SrcIP:     0x0100007f,
		DstIP:     0x0100007f,
		SrcPort:   0x5000,
		DstPort:   0xbb01,
		Protocol:  6,
		Timestamp: uint64(time.Now().UnixNano()),
	}
	copy(event.Signature[:], []byte("malware"))
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = formatTelemetryEvent(event)
	}
}
