package main

import (
	"fmt"
	"log"

	"github.com/cilium/ebpf"
)

func main() {
	m, err := ebpf.LoadPinnedMap("/sys/fs/bpf/hyperion_redirect_ports_map", nil)
	if err != nil {
		log.Fatalf("Load map: %v", err)
	}

	type portKey struct {
		Protocol uint8
		Port     uint16
	}
	var key portKey
	var val uint8

	iter := m.Iterate()
	for iter.Next(&key, &val) {
		fmt.Printf("Map Entry - Protocol: %d, Port: %d -> Action: %d\n", key.Protocol, key.Port, val)
	}
}
