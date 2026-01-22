package main

import (
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

// ANSI Color Codes
const (
	ColorReset  = "\033[0m"
	ColorGreen  = "\033[32m"
	ColorRed    = "\033[31m"
	ColorCyan   = "\033[36m"
	ColorYellow = "\033[33m"
)

// $BPF_CLANG_CFLAGS is automatically set by the Makefile
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS bpf ../kern/hyperion_core.c -- -I../common

func main() {
	// Custom logger without timestamp for cleaner CLI look
	log.SetFlags(0)

	if len(os.Args) < 2 {
		log.Fatalf("%s[!] Usage: %s -iface <interface>%s", ColorRed, os.Args[0], ColorReset)
	}
	ifaceName := os.Args[2]

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("%s[!] Loading objects failed: %v%s", ColorRed, err, ColorReset)
	}
	defer objs.Close()

	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		log.Fatalf("%s[!] Interface lookup failed: %s%s", ColorRed, err, ColorReset)
	}

	l, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.HyperionFilter,
		Interface: iface.Index,
	})
	if err != nil {
		log.Fatalf("%s[!] XDP Attach failed: %s%s", ColorRed, err, ColorReset)
	}
	defer l.Close()

	// --- STATUS OUTPUT ---
	log.Printf("%s[+] Hyperion M3.0 (DPI) Attached%s -> %s%s%s", ColorGreen, ColorReset, ColorCyan, ifaceName, ColorReset)
	log.Printf("%s[+] Active Defense Engine:%s %sSIGNATURE_SCAN (TCP)%s", ColorGreen, ColorReset, ColorYellow, ColorReset)
	log.Printf("%s[>] Target Signature:%s 'hack' (Hex: 0x68 0x61 0x63 0x6b)", ColorCyan, ColorReset)
	log.Printf("%s[!] Verdict:%s DROP IMMEDIATE", ColorRed, ColorReset)
	log.Printf("\nPress Ctrl+C to detach...")

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	<-stop

	log.Printf("\n%s[-] Detaching Hyperion...%s", ColorRed, ColorReset)
}