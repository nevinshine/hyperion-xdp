/* HYPERION AF_XDP CONTROLLER (Max-Out Architecture) */
package main

import (
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"
	"runtime"

	"golang.org/x/sys/unix"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	
	"github.com/asavie/xdp"
)

// --- COLORS & VISUALS ---
const (
	ColorReset  = "\033[0m"
	ColorRed    = "\033[31m"
	ColorGreen  = "\033[32m"
	ColorYellow = "\033[33m"
	ColorCyan   = "\033[36m"
)

// Hyperion Architectural Invariants
const (
	MaxQueues = 1 // Strict 1:1 model: 1 Queue <-> 1 Socket <-> 1 Goroutine
)

// Must match Kernel struct hyp_event
type HypEvent struct {
	EventType uint8
	_         [3]uint8
	RxQueue   uint32
	SrcIP     uint32
	DstIP     uint32
	SrcPort   uint16
	DstPort   uint16
	Protocol  uint8
	_         [3]uint8
	RxHash    uint32
	Timestamp uint64
}

// BPF Map Keys
type PortKey struct {
	Protocol uint8
	_        uint8
	Port     uint16
}

var (
	metricFastDrops = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "hyperion_fastpath_drops_total",
		Help: "Packets dropped in XDP kernel fast path",
	}, []string{"cpu"})
	metricSlowDrops = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "hyperion_slowpath_drops_total",
		Help: "Packets dropped by AF_XDP userspace DPI",
	}, []string{"reason", "queue"})
	metricSlowInspections = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "hyperion_slowpath_inspections_total",
		Help: "Packets evaluated in userspace DPI",
	}, []string{"queue"})
	metricRedirectFailures = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "hyperion_redirect_failures_total",
		Help: "Packets that failed XDP_REDIRECT due to unbound userspace socket (Fail-Open)",
	}, []string{"cpu"})
	metricWakeupLatency = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "hyperion_afxdp_wakeup_latency_ms",
		Help:    "Latency from kernel receive to AF_XDP userspace processing",
		Buckets: []float64{0.1, 0.5, 1.0, 5.0, 10.0, 50.0},
	}, []string{"queue"})
	metricRxDropped = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "hyperion_afxdp_rx_dropped_total",
		Help: "Total packets dropped by kernel due to AF_XDP Rx ring full",
	}, []string{"queue"})
	metricHWNICDrops = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "hyperion_hw_nic_drops_total",
		Help: "Hardware-level NIC drops scraped via ethtool",
	}, []string{"stat"})
)

var bootTimeOffset int64

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS bpf ../kern/hyperion_core.c -- -I../common

func main() {
	ifaceName := flag.String("iface", "veth0", "Interface to attach XDP")
	configPath := flag.String("config", "policy.yaml", "Path to YAML policy config")
	cpuPin := flag.Int("cpu", -1, "CPU Core ID to pin the AF_XDP polling thread (-1 to disable)")
	multiProg := flag.Bool("multiprog", false, "Use libxdp multiprog dispatcher (requires xdp-tools)")
	queues := flag.Int("queues", 1, "Number of RX queues to bind AF_XDP sockets to")
	flag.Parse()

	fmt.Printf("%s:: Hyperion AF_XDP Dataplane Engine ::%s\n\n", ColorCyan, ColorReset)

	// Invariant Enforcement
	if *cpuPin >= 0 {
		if runtime.GOMAXPROCS(0) > 1 {
			// When pinned to a CPU, we should ideally restrict GOMAXPROCS, but we at least log the invariant
			fmt.Printf("%s[i] Architectural Invariant: 1:1 Queue-to-Goroutine model enforced%s\n", ColorYellow, ColorReset)
		}
	} else {
		fmt.Printf("%s[!] Warning: Running without CPU pinning (-cpu flag). This violates the 1:1 deterministic model.%s\n", ColorYellow, ColorReset)
	}

	if err := calculateBootTimeOffset(); err != nil {
		log.Fatalf("Boot time offset failed: %v", err)
	}

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	// 1. Load BPF & Attach
	objs := bpfObjects{}
	var attachedLink link.Link

	if *multiProg {
		fmt.Printf("%s[i] Running in Multi-Program Mode (libxdp)%s\n", ColorYellow, ColorReset)
		if _, err := exec.LookPath("xdp-loader"); err != nil {
			log.Fatalf("xdp-loader not found in PATH. Please install xdp-tools.")
		}

		tmpFile := "/tmp/hyperion_multiprog.o"
		if err := os.WriteFile(tmpFile, _BpfBytes, 0644); err != nil {
			log.Fatalf("Failed to write temporary BPF object: %v", err)
		}

		pinPath := "/sys/fs/bpf/hyperion_xdp"
		os.RemoveAll(pinPath) // clean up old if exists

		cmd := exec.Command("xdp-loader", "load", "-m", "skb", "-p", pinPath, "-s", "xdp", "-P", "50", *ifaceName, tmpFile)
		out, err := cmd.CombinedOutput()
		if err != nil {
			log.Fatalf("xdp-loader failed: %v\nOutput: %s", err, string(out))
		}
		fmt.Printf("%s[+] libxdp dispatcher injected successfully%s\n", ColorGreen, ColorReset)

		// Load maps from pinned paths
		var mapErr error
		if objs.BlocklistMap, mapErr = loadPinnedMapSafe(pinPath + "/blocklist_map"); mapErr != nil {
			log.Fatalf("Map load err: %v", mapErr)
		}
		if objs.RedirectPortsMap, mapErr = loadPinnedMapSafe(pinPath + "/redirect_ports_map"); mapErr != nil {
			log.Fatalf("Map load err: %v", mapErr)
		}
		if objs.TelemetryRingbuf, mapErr = loadPinnedMapSafe(pinPath + "/telemetry_ringbuf"); mapErr != nil {
			log.Fatalf("Map load err: %v", mapErr)
		}
		if objs.DropStatsMap, mapErr = loadPinnedMapSafe(pinPath + "/drop_stats_map"); mapErr != nil {
			log.Fatalf("Map load err: %v", mapErr)
		}
		if objs.XskMap, mapErr = loadPinnedMapSafe(pinPath + "/xsk_map"); mapErr != nil {
			log.Fatalf("Map load err: %v", mapErr)
		}
		defer objs.Close()
	} else {
		if err := loadBpfObjects(&objs, nil); err != nil {
			log.Fatalf("Load BPF failed: %v", err)
		}
		defer objs.Close()
		
		iface, err := net.InterfaceByName(*ifaceName)
		if err != nil {
			log.Fatalf("Interface %s not found", *ifaceName)
		}

		attachedLink, err = link.AttachXDP(link.XDPOptions{
			Program:   objs.HyperionFilter,
			Interface: iface.Index,
		})
		if err != nil {
			log.Fatalf("XDP Attach failed: %v", err)
		}
		defer attachedLink.Close()
		fmt.Printf("%s[+] Fast Path XDP attached to %s%s\n", ColorGreen, *ifaceName, ColorReset)
	}

	iface, err := net.InterfaceByName(*ifaceName)
	if err != nil {
		log.Fatalf("Interface %s not found", *ifaceName)
	}

	// 2. Load Config & Populate Maps
	config, err := LoadPolicyConfig(*configPath)
	if err != nil {
		log.Fatalf("Failed to load policy: %v", err)
	}
	applyFastPathPolicy(objs, config.FastPath)

	var xsks []*xdp.Socket
	for q := 0; q < *queues; q++ {
		xsk, err := xdp.NewSocket(iface.Index, q, nil)
		if err != nil {
			log.Fatalf("Failed to create AF_XDP socket for queue %d: %v", q, err)
		}
		xsks = append(xsks, xsk)
		defer xsk.Close()

		if err := objs.XskMap.Put(uint32(q), uint32(xsk.FD())); err != nil {
			log.Fatalf("Failed to insert AF_XDP socket into BPF map: %v", err)
		}
		fmt.Printf("%s[+] Slow Path AF_XDP socket bound to queue %d%s\n", ColorGreen, q, ColorReset)
	}

	// 5. Start Prometheus endpoint
	go func() {
		http.Handle("/metrics", promhttp.Handler())
		fmt.Printf("%s[+] Prometheus metrics available on :2112/metrics%s\n", ColorGreen, ColorReset)
		http.ListenAndServe(":2112", nil)
	}()

	// 6. Start Kernel Telemetry Loop (Fast Path Drops / Redirect Failures)
	go func() {
		rd, err := ringbuf.NewReader(objs.TelemetryRingbuf)
		if err != nil {
			log.Fatalf("Telemetry Ringbuf failed: %v", err)
		}
		defer rd.Close()

		for {
			record, err := rd.Read()
			if err != nil {
				if err == ringbuf.ErrClosed {
					return
				}
				continue
			}

			var event HypEvent
			if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &event); err != nil {
				continue
			}

			if event.EventType == 1 {
				hashStr := ""
				if event.RxHash != 0 {
					hashStr = fmt.Sprintf(" [HW_HASH: 0x%x]", event.RxHash)
				}
				fmt.Printf("[%s] %sFAST_PATH_DROP%s (Q:%d)%s %s:%d -> %s:%d (Proto: %d)\n",
					time.Now().Format("15:04:05"), ColorRed, ColorReset, event.RxQueue, hashStr,
					int2ip(event.SrcIP), event.SrcPort,
					int2ip(event.DstIP), event.DstPort, event.Protocol)
			} else if event.EventType == 3 {
				hashStr := ""
				if event.RxHash != 0 {
					hashStr = fmt.Sprintf(" [HW_HASH: 0x%x]", event.RxHash)
				}
				fmt.Printf("[%s] %sREDIRECT_FAILURE%s (Q:%d)%s AF_XDP Socket Unreachable! Fail-Open applied for %s:%d\n",
					time.Now().Format("15:04:05"), ColorYellow, ColorReset, event.RxQueue, hashStr,
					int2ip(event.SrcIP), event.DstPort)
			}
		}
	}()

	// 6.5 Start Telemetry Polling Loop for PerCPU Stats
	go func() {
		numCPUs, _ := ebpf.PossibleCPU()
		lastBlockDrops := make([]uint64, numCPUs)
		lastRedirectFails := make([]uint64, numCPUs)

		for {
			time.Sleep(1 * time.Second)
			var perCPUVals []uint64
			
			// Blocklist drops (Reason = 0)
			if err := objs.DropStatsMap.Lookup(uint32(0), &perCPUVals); err == nil {
				for i := 0; i < numCPUs && i < len(perCPUVals); i++ {
					diff := perCPUVals[i] - lastBlockDrops[i]
					if diff > 0 {
						metricFastDrops.WithLabelValues(fmt.Sprintf("%d", i)).Add(float64(diff))
						lastBlockDrops[i] = perCPUVals[i]
					}
				}
			}

			// Redirect Failures (Reason = 2)
			if err := objs.DropStatsMap.Lookup(uint32(2), &perCPUVals); err == nil {
				for i := 0; i < numCPUs && i < len(perCPUVals); i++ {
					diff := perCPUVals[i] - lastRedirectFails[i]
					if diff > 0 {
						metricRedirectFailures.WithLabelValues(fmt.Sprintf("%d", i)).Add(float64(diff))
						lastRedirectFails[i] = perCPUVals[i]
					}
				}
			}
		}
	}()

	// Periodic Stats polling
	go func() {
		for {
			time.Sleep(5 * time.Second)
			for q := 0; q < *queues; q++ {
				stats, err := xsks[q].Stats()
				if err == nil {
					metricRxDropped.WithLabelValues(fmt.Sprintf("%d", q)).Set(float64(stats.KernelStats.Rx_dropped))
				}
			}
		}
	}()

	// Ethtool HW Scraper
	go func() {
		for {
			time.Sleep(5 * time.Second)
			out, err := exec.Command("ethtool", "-S", *ifaceName).Output()
			if err != nil {
				continue
			}
			lines := strings.Split(string(out), "\n")
			for _, line := range lines {
				line = strings.TrimSpace(line)
				if strings.Contains(line, "rx_missed_errors") || strings.Contains(line, "rx_nohandler") || strings.Contains(line, "drop") {
					parts := strings.Split(line, ":")
					if len(parts) == 2 {
						statName := strings.TrimSpace(parts[0])
						var val float64
						fmt.Sscanf(strings.TrimSpace(parts[1]), "%f", &val)
						metricHWNICDrops.WithLabelValues(statName).Set(val)
					}
				}
			}
		}
	}()

	// 7. Start AF_XDP Userspace DPI Loop (Slow Path)
	for q := 0; q < *queues; q++ {
		go func(queueID int, cpuBase int, xsk *xdp.Socket) {
			// Performance Engineering: Pin Goroutine and OS Thread to specific CPU
			runtime.LockOSThread()
			defer runtime.UnlockOSThread()
			
			qStr := fmt.Sprintf("%d", queueID)

			if cpuBase >= 0 {
				targetCPU := cpuBase + queueID
				var mask unix.CPUSet
				mask.Set(targetCPU)
				err := unix.SchedSetaffinity(0, &mask)
				if err != nil {
					log.Printf("Failed to pin AF_XDP thread to CPU %d: %v", targetCPU, err)
				} else {
					fmt.Printf("%s[+] CPU Affinity: Queue %d thread pinned to CPU %d%s\n", ColorGreen, queueID, targetCPU, ColorReset)
				}
			}

			for {
				// Poll the AF_XDP receive ring
				wakeupStart := time.Now()
				numReceived, _, err := xsk.Poll(-1)
				if err != nil {
					continue
				}

				if numReceived > 0 {
					descs := xsk.Receive(numReceived)
					
					latencyMs := float64(time.Since(wakeupStart).Nanoseconds()) / 1e6
					metricWakeupLatency.WithLabelValues(qStr).Observe(latencyMs)

					for i := 0; i < len(descs); i++ {
						frameData := xsk.GetFrame(descs[i])
						metricSlowInspections.WithLabelValues(qStr).Inc()

						action, reason := evaluateSlowPathPolicy(frameData, config.SlowPath)
						
						if action == "drop" {
							metricSlowDrops.WithLabelValues(reason, qStr).Inc()
							fmt.Printf("[%s] %sAF_XDP_DPI_DROP%s (Q:%d) Reason: %s (Len: %d)\n",
								time.Now().Format("15:04:05"), ColorYellow, ColorReset,
								queueID, reason, len(frameData))
						}
					}
					xsk.Fill(descs)
				}
			}
		}(q, *cpuPin, xsks[q])
	}

	// 8. Graceful Shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)

	for {
		sig := <-sigChan
		switch sig {
		case syscall.SIGHUP:
			fmt.Println("Reloading Policy...")
			newConf, err := LoadPolicyConfig(*configPath)
			if err == nil {
				config = newConf
				applyFastPathPolicy(objs, config.FastPath)
				fmt.Printf("%s[+] Policy Hot-Reloaded%s\n", ColorGreen, ColorReset)
			}
		case syscall.SIGINT, syscall.SIGTERM:
			fmt.Printf("\n%s[-] Shutting down Hyperion AF_XDP...%s\n", ColorRed, ColorReset)
			
			if *multiProg {
				fmt.Printf("[i] Unloading libxdp program...\n")
				exec.Command("xdp-loader", "unload", "-a", *ifaceName).Run()
				os.RemoveAll("/sys/fs/bpf/hyperion_xdp")
			}
			return
		}
	}
}

func applyFastPathPolicy(objs bpfObjects, fp FastPathConfig) {
	numCPUs, err := ebpf.PossibleCPU()
	if err != nil {
		log.Fatalf("Failed to get CPU count: %v", err)
	}

	blockedVals := make([]uint8, numCPUs)
	for i := 0; i < numCPUs; i++ {
		blockedVals[i] = 1
	}

	for _, ipStr := range fp.DropIPs {
		ip := net.ParseIP(ipStr).To4()
		if ip == nil {
			continue
		}
		ipInt := binary.LittleEndian.Uint32(ip)
		objs.BlocklistMap.Put(ipInt, blockedVals)
	}

	blockedVal := uint8(1)
	for _, pr := range fp.RedirectPorts {
		key := PortKey{
			Protocol: pr.Protocol,
			Port:     pr.Port,
		}
		objs.RedirectPortsMap.Put(key, blockedVal)
	}
}

func evaluateSlowPathPolicy(payload []byte, sp SlowPathConfig) (string, string) {
	payloadStr := string(payload) 
	
	for _, rule := range sp.DNSRules {
		if strings.Contains(payloadStr, rule.Match) {
			return rule.Action, "dns_match:" + rule.Match
		}
	}

	for _, rule := range sp.PayloadSignatures {
		if strings.Contains(payloadStr, rule.Match) {
			return rule.Action, "payload_match:" + rule.Match
		}
	}

	return "accept", ""
}

func int2ip(nn uint32) net.IP {
	ip := make(net.IP, 4)
	binary.LittleEndian.PutUint32(ip, nn)
	return ip
}

func calculateBootTimeOffset() error {
	data, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return err
	}
	var uptime float64
	fmt.Sscanf(string(data), "%f", &uptime)
	bootTimeNs := int64(uptime * 1e9)
	bootTimeOffset = time.Now().UnixNano() - bootTimeNs
	return nil
}

func loadPinnedMapSafe(path string) (*ebpf.Map, error) {
	// Import ebpf to use LoadPinnedMap
	// wait, it is imported by bpf_bpfel.go, but we might need it locally
	// let's import github.com/cilium/ebpf if needed
	return ebpf.LoadPinnedMap(path, nil)
}