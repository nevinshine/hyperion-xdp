package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"encoding/binary"

	"github.com/cilium/ebpf"
)

const IpcSocketPath = "/tmp/hyperion.sock"

type IpcRequest struct {
	Command string `json:"command"` // "add_signature", "block_ip"
	Payload string `json:"payload"`
}

type IpcResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}

// StartIPCServer starts the Unix Domain Socket listener for Cortex bridge commands.
func StartIPCServer(policyMap *ebpf.Map, blocklistMap *ebpf.Map) {
	// Clean up old socket if it exists
	os.Remove(IpcSocketPath)

	listener, err := net.Listen("unix", IpcSocketPath)
	if err != nil {
		log.Printf("%s[!] IPC Server failed to bind: %v%s\n", ColorRed, err, ColorReset)
		return
	}
	defer listener.Close()

	if err := os.Chmod(IpcSocketPath, 0666); err != nil {
		log.Printf("%s[!] IPC Server chmod failed: %v%s\n", ColorYellow, err, ColorReset)
	}

	fmt.Printf("%s[+] IPC Server listening on %s%s\n", ColorGreen, IpcSocketPath, ColorReset)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("IPC accept error: %v", err)
			continue
		}
		go handleIPCConnection(conn, policyMap, blocklistMap)
	}
}

func handleIPCConnection(conn net.Conn, policyMap *ebpf.Map, blocklistMap *ebpf.Map) {
	defer conn.Close()

	var req IpcRequest
	decoder := json.NewDecoder(conn)
	if err := decoder.Decode(&req); err != nil {
		sendIpcResponse(conn, false, "Invalid JSON payload")
		return
	}

	switch req.Command {
	case "add_signature":
		handleAddSignature(req.Payload, policyMap, conn)
	case "block_ip":
		handleBlockIP(req.Payload, blocklistMap, conn)
	default:
		sendIpcResponse(conn, false, "Unknown command")
	}
}

func handleAddSignature(payload string, policyMap *ebpf.Map, conn net.Conn) {
	// Find the first empty slot or just override max. Wait, policyMap max entries is 2!
	// We'll just overwrite slot 0 for simplicity if we must, or ideally scan for inactive.
	// Since this is a prototype, let's just write to slot 1 (since index 0 might be used by signatures.txt).
	var pol Policy
	sigBytes := []byte(payload)
	if len(sigBytes) > 8 {
		sigBytes = sigBytes[:8]
	}
	copy(pol.Signature[:], sigBytes)
	pol.SigLen = uint8(len(sigBytes))
	pol.Active = 1
	
	// Write to slot 1
	if err := policyMap.Put(uint32(1), pol); err != nil {
		sendIpcResponse(conn, false, fmt.Sprintf("Failed to update map: %v", err))
		return
	}
	
	fmt.Printf("%s[IPC] Added payload signature: %s%s\n", ColorYellow, payload, ColorReset)
	sendIpcResponse(conn, true, "Signature added successfully")
}

func handleBlockIP(ipStr string, blocklistMap *ebpf.Map, conn net.Conn) {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		sendIpcResponse(conn, false, "Invalid IP address format")
		return
	}
	
	ip4 := ip.To4()
	if ip4 == nil {
		sendIpcResponse(conn, false, "Only IPv4 is supported")
		return
	}

	// Parse to uint32 using LittleEndian so it matches the network byte order struct layout exactly
	ipUint := binary.LittleEndian.Uint32(ip4)
	
	flag := uint8(1) // Just a dummy value indicating it is blocked
	if err := blocklistMap.Put(&ipUint, &flag); err != nil {
		sendIpcResponse(conn, false, fmt.Sprintf("Failed to add to blocklist: %v", err))
		return
	}
	
	fmt.Printf("%s[IPC] Layer 2 Blocklist Updated: %s%s\n", ColorRed, ipStr, ColorReset)
	sendIpcResponse(conn, true, "IP blocked successfully")
}

func sendIpcResponse(conn net.Conn, success bool, message string) {
	resp := IpcResponse{
		Success: success,
		Message: message,
	}
	encoder := json.NewEncoder(conn)
	encoder.Encode(resp)
}
