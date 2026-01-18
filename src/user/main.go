package main

// 1. The Magic Generation Command
// This tells 'go generate' to look one folder up (../kern) for the C code
// and output the Go bindings right here in src/user.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpf -output-dir . -type xdp_md xdp ../kern/hyperion_core.c

import (
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf/link"
)

func main() {
	// 2. Load the compiled eBPF code (The "Brain")
	objs := xdpObjects{}
	if err := loadXdpObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	// 3. Select the Interface
	// TODO: Change "lo" to your actual interface (e.g., "eth0", "wlan0") for real traffic
	ifaceName := "lo" 
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		log.Fatalf("lookup network iface %q: %v", ifaceName, err)
	}

	// 4. Attach the "Brain" to the Network Driver
	l, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.HyperionFilter,
		Interface: iface.Index,
	})
	if err != nil {
		log.Fatalf("could not attach XDP program: %v", err)
	}
	defer l.Close()

	log.Printf("Hyperion Active on %s (Dropping 1.2.3.4). Press Ctrl+C to stop.", ifaceName)

	// 5. Keep running until Ctrl+C
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	<-stop
	
	log.Println("Detaching Hyperion...")
}
