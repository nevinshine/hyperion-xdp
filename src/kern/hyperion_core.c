#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#ifndef ETH_P_IP
#define ETH_P_IP 0x0800
#endif

#ifndef IPPROTO_TCP
#define IPPROTO_TCP 6
#endif

#ifndef IPPROTO_UDP
#define IPPROTO_UDP 17
#endif

// Dynamic Capability Probing
// FIX: We now export two separate programs and dynamically patch the ELF CollectionSpec in Go
// to bypass early BTF resolution for kfuncs.
// -----------------------------------------------------------------------------
// HYPERION FAST PATH (KERNEL XDP)
// - Bounded Checks
// - IP Blocklisting (Drop)
// - Port Redirection to AF_XDP (Slow Path)
// -----------------------------------------------------------------------------

// O(1) IP Blocklist Map
struct {
    __uint(type, BPF_MAP_TYPE_LRU_PERCPU_HASH);
    __type(key, __u32);
    __type(value, __u8); // 1 = blocked
    __uint(max_entries, 65536);
} blocklist_map SEC(".maps");

// Lock-Free Fast Path Telemetry Counters
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 5); // 0=Blocklist, 1=Malformed, 2=Redirect_Failure, 3=Watchdog_Degraded, 4=Redirect_Match
} drop_stats_map SEC(".maps");

// Watchdog Map: Userspace heartbeat timestamp
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 1);
} watchdog_map SEC(".maps");

// 50ms stall threshold before degrading to XDP_PASS
#define STALL_THRESHOLD_NS 50000000ULL

// Runtime-rewritten constant: number of AF_XDP queues bound by userspace.
// When cfg_num_queues == 1, we force queue 0 (safe for loopback/veth where
// rx_queue_index erroneously reports the CPU ID in Generic XDP mode).
// When cfg_num_queues > 1, we use ctx->rx_queue_index for proper RSS fan-out.
volatile const __u32 cfg_num_queues = 1;

struct port_key {
    __u8 protocol;
    __u8 pad;
    __u16 port;
};

// Map of ports to redirect to userspace DPI
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct port_key);
    __type(value, __u8); // 1 = redirect
    __uint(max_entries, 1024);
} redirect_ports_map SEC(".maps");

// AF_XDP Socket Map for userspace handoff
struct {
    __uint(type, BPF_MAP_TYPE_XSKMAP);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 64);
} xsk_map SEC(".maps");

// Fast Path Telemetry (Drops only, to reduce ringbuf pressure)
struct hyp_event {
    __u8 event_type;    // 1=DROP
    __u8 _pad1[3];
    __u32 rx_queue;
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8 protocol;
    __u8 _pad2[3];
    __u32 rx_hash;
    __u64 timestamp;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 16); // 64KB for telemetry
} telemetry_ringbuf SEC(".maps");

struct cursor {
    void *pos;
    void *end;
};

static __attribute__((always_inline)) void increment_drop_stat(__u32 reason) {
    __u64 *val = bpf_map_lookup_elem(&drop_stats_map, &reason);
    if (val) {
        (*val)++;
    }
}

static __attribute__((always_inline)) void emit_drop_telemetry(struct xdp_md *ctx, __u32 sip, __u32 dip, __u16 sport, __u16 dport, __u8 proto, bool hw_metadata) {
    struct hyp_event *evt = bpf_ringbuf_reserve(&telemetry_ringbuf, sizeof(*evt), 0);
    if (!evt) return;
    evt->event_type = 1; // DROP
    evt->rx_queue = ctx->rx_queue_index;
    evt->src_ip = sip;
    evt->dst_ip = dip;
    evt->src_port = sport;
    evt->dst_port = dport;
    evt->protocol = proto;
    
    evt->rx_hash = 0;
    if (hw_metadata) {
        if (bpf_xdp_metadata_rx_hash) {
            __u32 type = 0;
            bpf_xdp_metadata_rx_hash(ctx, &evt->rx_hash, (void *)&type);
        }
    }

    evt->timestamp = 0;
    if (hw_metadata) {
        if (bpf_xdp_metadata_rx_timestamp) {
            bpf_xdp_metadata_rx_timestamp(ctx, &evt->timestamp);
        }
    }
    if (evt->timestamp == 0) {
        evt->timestamp = bpf_ktime_get_ns();
    }
    
    bpf_ringbuf_submit(evt, 0);
}

static __attribute__((always_inline)) int hyperion_filter_main(struct xdp_md *ctx, bool hw_metadata) {
    struct cursor c;
    c.pos = (void *)(long)ctx->data;
    c.end = (void *)(long)ctx->data_end;

    // 1. Ethernet Header
    struct ethhdr *eth = c.pos;
    if ((void *)(eth + 1) > c.end) return XDP_PASS;
    c.pos += sizeof(struct ethhdr);

    if (eth->h_proto != bpf_htons(ETH_P_IP)) return XDP_PASS;

    // 2. IP Header
    struct iphdr *ip = c.pos;
    if ((void *)(ip + 1) > c.end) return XDP_PASS;
    
    // Verifier bound check
    if (ip->ihl < 5) return XDP_PASS; 
    c.pos += ip->ihl * 4;

    __u32 src_ip = ip->saddr;
    __u32 dst_ip = ip->daddr;
    __u8 protocol = ip->protocol;

    // Fast Path L3 Blocklist Evaluation
    __u8 *is_blocked = bpf_map_lookup_elem(&blocklist_map, &src_ip);
    if (is_blocked && *is_blocked == 1) {
        increment_drop_stat(0); // 0 = Blocklist Drop
        emit_drop_telemetry(ctx, src_ip, dst_ip, 0, 0, protocol, hw_metadata);
        return XDP_DROP;
    }

    __u16 src_port = 0;
    __u16 dst_port = 0;

    // 3. Extract Transport Layer
    if (protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = c.pos;
        if ((void *)(tcp + 1) > c.end) return XDP_PASS;
        src_port = tcp->source;
        dst_port = tcp->dest;
    } else if (protocol == IPPROTO_UDP) {
        struct udphdr *udp = c.pos;
        if ((void *)(udp + 1) > c.end) return XDP_PASS;
        src_port = udp->source;
        dst_port = udp->dest;
    } else {
        return XDP_PASS;
    }

    // 4. Port-based Redirect Check
    struct port_key pkey = {};
    pkey.protocol = protocol;
    pkey.port = bpf_ntohs(dst_port); // Convert to host byte order for easier YAML config match

    __u8 *should_redirect = bpf_map_lookup_elem(&redirect_ports_map, &pkey);
    if (should_redirect && *should_redirect == 1) {
        increment_drop_stat(4); // 4 = Redirect Match (Diagnostic)
        
        // Synchronous Watchdog Check
        __u32 wd_key = 0;
        __u64 *last_hb = bpf_map_lookup_elem(&watchdog_map, &wd_key);
        __u64 now = bpf_ktime_get_ns();
        if (last_hb && (now - *last_hb) > STALL_THRESHOLD_NS) {
            increment_drop_stat(3); // 3 = Watchdog Degradation (not actually dropped, but logged as fallback)
            // Note: In production we'd emit a dedicated WATCHDOG_DEGRADED telemetry event.
            // For now, we instantly fail-open to preserve O(1) forwarding.
            return XDP_PASS;
        }

        // Check if AF_XDP socket is actually bound to this queue
        // When single-queue (loopback/veth), force queue 0 since Generic XDP
        // populates rx_queue_index with the CPU ID, not the hardware queue.
        // When multi-queue (real NIC), use rx_queue_index for RSS fan-out.
        __u32 q_idx = (cfg_num_queues > 1) ? ctx->rx_queue_index : 0;
        __u32 *xsk = bpf_map_lookup_elem(&xsk_map, &q_idx);
        if (!xsk) {
            increment_drop_stat(2); // 2 = Redirect Failure
            // Fail-Open: Socket is dead or unbound. Emit telemetry and XDP_PASS.
            struct hyp_event *evt = bpf_ringbuf_reserve(&telemetry_ringbuf, sizeof(*evt), 0);
            if (evt) {
                evt->event_type = 3; // REDIRECT_FAILURE
                evt->rx_queue = ctx->rx_queue_index;
                evt->src_ip = src_ip;
                evt->dst_ip = dst_ip;
                evt->src_port = bpf_ntohs(src_port);
                evt->dst_port = bpf_ntohs(dst_port);
                evt->protocol = protocol;
                
                evt->rx_hash = 0;
                evt->rx_hash = 0;
                if (hw_metadata) {
                    if (bpf_xdp_metadata_rx_hash) {
                        __u32 type = 0;
                        bpf_xdp_metadata_rx_hash(ctx, &evt->rx_hash, (void *)&type);
                    }
                }

                evt->timestamp = 0;
                if (hw_metadata) {
                    if (bpf_xdp_metadata_rx_timestamp) {
                        bpf_xdp_metadata_rx_timestamp(ctx, &evt->timestamp);
                    }
                }
                if (evt->timestamp == 0) {
                    evt->timestamp = bpf_ktime_get_ns();
                }
                
                bpf_ringbuf_submit(evt, 0);
            }
            return XDP_PASS;
        }
        
        // Handoff to AF_XDP userspace
        return bpf_redirect_map(&xsk_map, q_idx, XDP_PASS);
    }

    return XDP_PASS;
}

SEC("xdp")
int hyperion_filter_generic(struct xdp_md *ctx) {
    return hyperion_filter_main(ctx, false);
}

SEC("xdp/hw")
int hyperion_filter_hw(struct xdp_md *ctx) {
    return hyperion_filter_main(ctx, true);
}

char _license[] SEC("license") = "GPL";