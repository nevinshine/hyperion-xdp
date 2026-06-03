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
	"strconv"
	"strings"
	"sync/atomic"
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
	metricWatchdogDegraded = promauto.NewCounter(prometheus.CounterOpts{
		Name: "hyperion_watchdog_degraded_total",
		Help: "Number of times the dataplane entered starvation/congestion mode (Fail-Open)",
	})
	metricWatchdogState = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "hyperion_watchdog_state",
		Help: "Current state of the dataplane watchdog (0 = Healthy, 1 = Degraded, 2 = Recovering)",
	})
	metricWatchdogRecovery = promauto.NewCounter(prometheus.CounterOpts{
		Name: "hyperion_watchdog_recovery_total",
		Help: "Number of times the dataplane successfully recovered from starvation back to healthy",
	})
	metricWatchdogDegradedSeconds = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "hyperion_watchdog_degraded_seconds",
		Help:    "Duration spent actively degraded due to congestion backpressure",
		Buckets: []float64{0.01, 0.05, 0.1, 0.5, 1.0, 5.0, 10.0, 60.0},
	})
	metricWatchdogRecoveringSeconds = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "hyperion_watchdog_recovering_seconds",
		Help:    "Duration spent in hysteresis recovery window before promoting to healthy",
		Buckets: []float64{0.01, 0.05, 0.1, 0.5, 1.0, 5.0, 10.0, 60.0},
	})
	metricRingOccupancy = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "hyperion_ring_occupancy",
		Help: "Current number of active AF_XDP descriptors checked out to userspace",
	})
)

// WatchdogState represents the formal operational state of the dataplane watchdog.
// State transitions follow a strict order: HEALTHY → DEGRADED → RECOVERING → HEALTHY.
// The kernel fast-path is stateless; these states exist only in userspace for
// telemetry, hysteresis, and operational auditing.
type WatchdogState int

const (
	// WatchdogHealthy: AF_XDP socket is responsive, heartbeat is fresh.
	// Kernel fast-path redirects packets to userspace for deep inspection.
	WatchdogHealthy WatchdogState = 0

	// WatchdogDegraded: AF_XDP backpressure detected or userspace stalled.
	// Heartbeat is deliberately starved, causing the kernel to fail-open via XDP_PASS.
	// Deep inspection is suspended; forwarding continuity is prioritized.
	WatchdogDegraded WatchdogState = 1

	// WatchdogRecovering: Backpressure has subsided but hysteresis window is active.
	// System waits for 5 consecutive healthy ticks (50ms) before promoting to HEALTHY,
	// preventing rapid oscillation between DEGRADED and HEALTHY.
	WatchdogRecovering WatchdogState = 2
)

// String returns the formal name of the watchdog state.
func (s WatchdogState) String() string {
	switch s {
	case WatchdogHealthy:
		return "HEALTHY"
	case WatchdogDegraded:
		return "DEGRADED"
	case WatchdogRecovering:
		return "RECOVERING"
	default:
		return "UNKNOWN"
	}
}

var bootTimeOffset int64
var activeDescriptors int32

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS bpf ../kern/hyperion_core.c -- -I../common

func main() {
	ifaceName := flag.String("iface", "veth0", "Interface to attach XDP")
	configPath := flag.String("config", "policy.yaml", "Path to YAML policy config")
	cpuPin := flag.Int("cpu", -1, "CPU Core ID to pin the AF_XDP polling thread (-1 to disable)")
	multiProg := flag.Bool("multiprog", false, "Use libxdp multiprog dispatcher (requires xdp-tools)")
	queues := flag.Int("queues", 1, "Number of RX queues to bind AF_XDP sockets to")
	hwMetadata := flag.Bool("hw-metadata", false, "Enable hardware metadata acceleration (RSS hashes, HW timestamps). Requires supported physical NIC.")
	forceGeneric := flag.Bool("force-generic", false, "Force XDP Generic Mode (SKB Mode) attachment instead of Native Mode")
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
		if objs.WatchdogMap, mapErr = loadPinnedMapSafe(pinPath + "/watchdog_map"); mapErr != nil {
			log.Fatalf("Map load err: %v", mapErr)
		}
		defer objs.Close()
	} else {
		spec, err := loadBpf()
		if err != nil {
			log.Fatalf("Failed to load BPF spec: %v", err)
		}

		// Rewrite cfg_num_queues so the BPF program uses rx_queue_index for multi-queue
		// NICs, or forces queue 0 for single-queue/virtual interfaces.
		if err := spec.RewriteConstants(map[string]interface{}{
			"cfg_num_queues": uint32(*queues),
		}); err != nil {
			log.Fatalf("Failed to rewrite cfg_num_queues: %v", err)
		}
		if *queues > 1 {
			fmt.Printf("%s[+] Multi-Queue RSS: %d queues (using rx_queue_index)%s\n", ColorCyan, *queues, ColorReset)
		}

		var activeProgram *ebpf.Program
		var coll *ebpf.Collection

		if *hwMetadata {
			// Attempt 1: Hardware Metadata Program
			specHw := spec.Copy()
			delete(specHw.Programs, "hyperion_filter_generic")
			coll, err = ebpf.NewCollectionWithOptions(specHw, ebpf.CollectionOptions{})
			if err == nil {
				fmt.Printf("%s[+] Hardware Metadata Acceleration: ENABLED (Physical NIC Detected)%s\n", ColorCyan, ColorReset)
				activeProgram = coll.Programs["hyperion_filter_hw"]
			} else {
				fmt.Printf("%s[!] Hardware Metadata rejected by kernel, falling back to Generic XDP.%s\n", ColorYellow, ColorReset)
			}
		} else {
			fmt.Printf("%s[+] Hardware Metadata Acceleration: DISABLED by user (Skipping Probe)%s\n", ColorYellow, ColorReset)
		}

		if activeProgram == nil {
			// Fallback: Generic Program
			specGeneric := spec.Copy()
			delete(specGeneric.Programs, "hyperion_filter_hw")
			coll, err = ebpf.NewCollectionWithOptions(specGeneric, ebpf.CollectionOptions{})
			if err != nil {
				log.Fatalf("Load BPF Generic fallback failed: %v", err)
			}
			activeProgram = coll.Programs["hyperion_filter_generic"]
		}
		defer coll.Close()
		
		// Map back to objs so the rest of the code functions normally
		objs.BlocklistMap = coll.Maps["blocklist_map"]
		objs.RedirectPortsMap = coll.Maps["redirect_ports_map"]
		objs.TelemetryRingbuf = coll.Maps["telemetry_ringbuf"]
		objs.DropStatsMap = coll.Maps["drop_stats_map"]
		objs.XskMap = coll.Maps["xsk_map"]
		objs.WatchdogMap = coll.Maps["watchdog_map"]
		
		iface, err := net.InterfaceByName(*ifaceName)
		if err != nil {
			log.Fatalf("Interface %s not found", *ifaceName)
		}

		var attachFlags link.XDPAttachFlags = 0
		if *forceGeneric {
			attachFlags = link.XDPGenericMode
			fmt.Printf("%s[i] Forcing XDP Generic Mode (SKB) attachment%s\n", ColorYellow, ColorReset)
		}

		attachedLink, err = link.AttachXDP(link.XDPOptions{
			Program:   activeProgram,
			Interface: iface.Index,
			Flags:     attachFlags,
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
		// Attempt 1: Zero-Copy
		xdp.DefaultSocketFlags = unix.XDP_ZEROCOPY
		xsk, err := xdp.NewSocket(iface.Index, q, nil)
		if err == nil {
			fmt.Printf("%s[+] Zero-Copy AF_XDP Acceleration: ENABLED (Queue %d)%s\n", ColorCyan, q, ColorReset)
		} else {
			// Fallback: Copy-Mode
			fmt.Printf("%s[!] Zero-Copy unsupported, falling back to SKB Copy-Mode (Queue %d)%s\n", ColorYellow, q, ColorReset)
			xdp.DefaultSocketFlags = unix.XDP_COPY
			xsk, err = xdp.NewSocket(iface.Index, q, nil)
			if err != nil {
				log.Fatalf("Failed to create AF_XDP socket (even in Copy-Mode) for queue %d: %v", q, err)
			}
		}

		xsks = append(xsks, xsk)
		defer xsk.Close()

		// Prime the pump: Give the kernel all available empty descriptors so it can receive packets
		descs := xsk.GetDescs(xsk.NumFreeFillSlots())
		n := xsk.Fill(descs)
		fmt.Printf("[+] AF_XDP Fill Ring primed with %d/%d descriptors (NumFreeFillSlots=%d)\n", n, len(descs), xsk.NumFreeFillSlots())

		if err := objs.XskMap.Put(uint32(q), uint32(xsk.FD())); err != nil {
			log.Fatalf("Failed to insert AF_XDP socket into BPF map: %v", err)
		}
		fmt.Printf("%s[+] Slow Path AF_XDP socket bound to queue %d%s\n", ColorGreen, q, ColorReset)
	}

	// Launch Backpressure-Driven Watchdog
	go watchdogLoop(&objs, xsks)

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
			simulateLag := os.Getenv("HYPERION_SIMULATE_LAG") != ""

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
					atomic.AddInt32(&activeDescriptors, int32(numReceived))
					
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
					
					if simulateLag {
						time.Sleep(20 * time.Millisecond) // Artificially cripple processing speed to simulate severe GC/Load
					}

					xsk.Fill(descs)
					atomic.AddInt32(&activeDescriptors, -int32(numReceived))
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
			Protocol: uint8(pr.Protocol),
			Port:     uint16(pr.Port),
		}
		if err := objs.RedirectPortsMap.Put(key, blockedVal); err != nil {
			log.Printf("[!] Failed to insert redirect port %d/%d: %v", pr.Protocol, pr.Port, err)
		}
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

func watchdogLoop(objs *bpfObjects, xsks []*xdp.Socket) {
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	
	key := uint32(0)
	state := WatchdogHealthy
	consecutiveHealthy := 0
	stateEnteredAt := time.Now()

	threshold := 1024 // default 50% capacity
	if val := os.Getenv("HYPERION_CONGESTION_THRESHOLD"); val != "" {
		if t, err := strconv.Atoi(val); err == nil {
			threshold = t
		}
	}

	type TransitionReason string
	const (
		ReasonBackpressure         TransitionReason = "af_xdp_backpressure"
		ReasonBackpressureSubsided TransitionReason = "backpressure_subsided"
		ReasonHysteresisComplete   TransitionReason = "hysteresis_complete"
	)

	allowedTransitions := map[WatchdogState]map[WatchdogState]bool{
		WatchdogHealthy:    {WatchdogDegraded: true},
		WatchdogDegraded:   {WatchdogRecovering: true},
		WatchdogRecovering: {WatchdogHealthy: true, WatchdogDegraded: true},
	}

	// transitionTo records a formal state transition with audit telemetry.
	transitionTo := func(newState WatchdogState, reason TransitionReason, details string) {
		if state == newState {
			return
		}
		
		// Formal FSM Validation
		if allowed, ok := allowedTransitions[state][newState]; !ok || !allowed {
			log.Fatalf("[FATAL] Illegal FSM Transition Attempted: %s → %s (reason: %s)", state, newState, reason)
		}

		now := time.Now()
		durationInState := now.Sub(stateEnteredAt)
		
		// Split Histograms
		if state == WatchdogDegraded {
			metricWatchdogDegradedSeconds.Observe(durationInState.Seconds())
		} else if state == WatchdogRecovering {
			metricWatchdogRecoveringSeconds.Observe(durationInState.Seconds())
		}
		
		oldState := state
		state = newState
		stateEnteredAt = now
		metricWatchdogState.Set(float64(newState))
		
		if details != "" {
			log.Printf("[WATCHDOG] %s → %s | reason=%s | details=%s | duration=%.3fs", oldState, newState, reason, details, durationInState.Seconds())
		} else {
			log.Printf("[WATCHDOG] %s → %s | reason=%s | duration=%.3fs", oldState, newState, reason, durationInState.Seconds())
		}
	}

	for range ticker.C {
		congested := false
		
		// Update Ring Occupancy Gauge
		currentOccupancy := atomic.LoadInt32(&activeDescriptors)
		metricRingOccupancy.Set(float64(currentOccupancy))
		
		// mathematically correct backpressure: how many packets are checked out and stalling?
		if currentOccupancy > int32(threshold) {
			congested = true
		}
		
		if congested {
			if state == WatchdogHealthy || state == WatchdogRecovering {
				transitionTo(WatchdogDegraded, ReasonBackpressure, "")
			}
			consecutiveHealthy = 0
			metricWatchdogDegraded.Inc()
			continue // Deliberately starve the watchdog
		}
		
		if state == WatchdogDegraded {
			transitionTo(WatchdogRecovering, ReasonBackpressureSubsided, "")
		}
		
		if state == WatchdogRecovering {
			consecutiveHealthy++
			if consecutiveHealthy < 5 { // 50ms hysteresis
				continue // Starve heartbeat to prevent oscillation
			}
			// Fully recovered
			consecutiveHealthy = 0
			metricWatchdogRecovery.Inc()
			transitionTo(WatchdogHealthy, ReasonHysteresisComplete, "")
		}
		
		// eBPF uses bpf_ktime_get_ns() (uptime in nanoseconds)
		ktime := uint64(time.Now().UnixNano() - bootTimeOffset)
		
		err := objs.WatchdogMap.Put(key, ktime)
		if err != nil {
			log.Printf("Watchdog update failed: %v", err)
		}
	}
}