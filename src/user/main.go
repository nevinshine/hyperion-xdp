/* HYPERION CONTROLLER M4.6 (Visual Upgrade) */
package main

import (
    "bufio"
    "bytes"
    "encoding/binary"
    "flag"
    "fmt"
    "log"
    "net"
    "os"
    "os/signal"
    "strings"
    "syscall"
    "time"

    "github.com/cilium/ebpf"
    "github.com/cilium/ebpf/link"
    "github.com/cilium/ebpf/ringbuf"
    "github.com/cilium/ebpf/rlimit"
)

// --- COLORS & VISUALS ---
const (
    ColorReset  = "\033[0m"
    ColorRed    = "\033[31m"
    ColorGreen  = "\033[32m"
    ColorYellow = "\033[33m"
    ColorBlue   = "\033[34m"
    ColorPurple = "\033[35m"
    ColorCyan   = "\033[36m"
    ColorWhite  = "\033[37m"
)

const (
    ConfigFile = "signatures.txt"
    MaxRules   = 2
)

// Must match Kernel Struct (struct policy_t)
type Policy struct {
    Signature [8]uint8
    SigLen    uint8
    Active    uint8
    Pad       [2]uint8 // FIXED: Aligns to 12 bytes
}

// Must match Kernel Struct (struct event_t)
type AlertEvent struct {
    SrcIP   uint32
    DstIP   uint32
    SrcPort uint16   // FIXED: Added to match C
    DstPort uint16   // FIXED: Added to match C
    Action  uint32   // FIXED: Renamed from RuleID (since C sends Action)
    Snippet [8]byte
}

var loadedSigs []string

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS bpf ../kern/hyperion_core.c -- -I../common

func main() {
    // Default to 'wlp1s0' if not specified
    ifaceName := flag.String("iface", "wlp1s0", "Interface to attach XDP")
    flag.Parse()

    printBanner()

    // 1. Init
    if err := rlimit.RemoveMemlock(); err != nil {
        log.Fatal(err)
    }

    objs := bpfObjects{}
    if err := loadBpfObjects(&objs, nil); err != nil {
        log.Fatalf("%s[!] Load BPF failed: %v%s", ColorRed, err, ColorReset)
    }
    defer objs.Close()

    // 2. Load Config
    if err := reloadSignatures(objs.PolicyMap); err != nil {
        log.Printf("%s[!] Initial load warning: %v%s", ColorYellow, err, ColorReset)
    }

    // 3. Attach XDP
    iface, err := net.InterfaceByName(*ifaceName)
    if err != nil {
        log.Fatalf("%s[!] Interface %s not found%s", ColorRed, *ifaceName, ColorReset)
    }

    l, err := link.AttachXDP(link.XDPOptions{
        Program:   objs.HyperionFilter,
        Interface: iface.Index,
    })
    if err != nil {
        log.Fatalf("%s[!] XDP Attach failed: %v%s", ColorRed, err, ColorReset)
    }
    defer l.Close()

    // 4. Telemetry Loop
    rd, err := ringbuf.NewReader(objs.AlertRingbuf)
    if err != nil {
        log.Fatalf("%s[!] Ringbuf failed: %v%s", ColorRed, err, ColorReset)
    }
    defer rd.Close()

    fmt.Printf("%s[+] Hyperion Active on %s%s\n", ColorGreen, *ifaceName, ColorReset)
    fmt.Printf("%s[i] PID: %d (Run 'kill -HUP %d' to reload)%s\n", ColorCyan, os.Getpid(), os.Getpid(), ColorReset)
    fmt.Println(strings.Repeat("-", 60))
    fmt.Printf("%sWaiting for threats...%s\n", ColorWhite, ColorReset)

    go func() {
        for {
            record, err := rd.Read()
            if err != nil {
                if err == ringbuf.ErrClosed {
                    return
                }
                continue
            }

            var event AlertEvent
            // Binary read must match struct layout exactly
            if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &event); err != nil {
                log.Printf("Failed to parse event: %v", err)
                continue
            }

            // NOTE: Currently C sends Action=1 (Drop), not the Rule Index.
            // So we just log "BLOCKED" generally.
            payloadStr := string(event.Snippet[:])
            // sanitize string
            payloadStr = strings.ReplaceAll(payloadStr, "\n", ".")
            payloadStr = strings.ReplaceAll(payloadStr, "\r", ".")

            // ALERT LOG STYLE
            fmt.Printf("%s[%s] ALERT: Blocked Traffic from %s -> Payload: [%s]%s\n",
                ColorRed,
                time.Now().Format("15:04:05"),
                int2ip(event.SrcIP),
                payloadStr,
                ColorReset)
        }
    }()

    // 5. Signal Handling
    sigChan := make(chan os.Signal, 1)
    signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)

    for {
        sig := <-sigChan
        switch sig {
        case syscall.SIGHUP:
            fmt.Printf("\n%s[!] Reloading signatures...%s\n", ColorYellow, ColorReset)
            if err := reloadSignatures(objs.PolicyMap); err != nil {
                fmt.Printf("%s[-] Reload Error: %v%s\n", ColorRed, err, ColorReset)
            } else {
                fmt.Printf("%s[+] Reload Complete.%s\n", ColorGreen, ColorReset)
            }
        case syscall.SIGINT, syscall.SIGTERM:
            fmt.Printf("\n%s[-] Shutting down Hyperion.%s\n", ColorRed, ColorReset)
            return
        }
    }
}

func reloadSignatures(m *ebpf.Map) error {
    f, err := os.Open(ConfigFile)
    if err != nil {
        return err
    }
    defer f.Close()

    var newSigs []string
    sc := bufio.NewScanner(f)
    for sc.Scan() {
        line := strings.TrimSpace(sc.Text())
        if line != "" && !strings.HasPrefix(line, "#") {
            newSigs = append(newSigs, line)
        }
    }

    if len(newSigs) > MaxRules {
        return fmt.Errorf("Too many rules (Max %d)", MaxRules)
    }

    for i := 0; i < MaxRules; i++ {
        var pol Policy
        if i < len(newSigs) {
            s := newSigs[i]
            if len(s) > 8 {
                s = s[:8]
            }
            copy(pol.Signature[:], []byte(s))
            pol.SigLen = uint8(len(s)) // FIXED: Type cast
            pol.Active = 1
            fmt.Printf("    %s-> Loaded Rule %d: %s%s\n", ColorBlue, i, s, ColorReset)
        } else {
            pol.Active = 0
        }
        
        // FIXED: Use uint32(i) for key to match BPF definition
        if err := m.Put(uint32(i), pol); err != nil {
            return err
        }
    }
    loadedSigs = newSigs
    return nil
}

func int2ip(nn uint32) net.IP {
    ip := make(net.IP, 4)
    binary.LittleEndian.PutUint32(ip, nn)
    return ip
}

func printBanner() {
    banner := `
%s    __  __                      _
   / / / /_  ______  ___  _____(_)___  ____
  / /_/ / / / / __ \/ _ \/ ___/ / __ \/ __ \
 / __  / /_/ / /_/ /  __/ /  / / /_/ / / / /
/_/ /_/\__, / .___/\___/_/  /_/\____/_/ /_/
      /____/_/

    %s:: Hyperion XDP Engine vM4.6 ::%s
`
    fmt.Printf(banner, ColorCyan, ColorPurple, ColorReset)
    fmt.Println()
}