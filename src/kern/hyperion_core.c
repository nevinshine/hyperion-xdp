/* HYPERION M2: Compatibility Mode */
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/* Map definitions */
#define XDP_PASS 2
#define XDP_DROP 1

/* CONFIG: DDoS Threshold */
#define FLOOD_THRESHOLD 10

/* * M2 ARCHITECTURE: Flow State Table
 * We explicitly define the map structure for compatibility
 */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);   // Source IP
    __type(value, __u64); // Packet Count
} flow_tracker SEC(".maps");

SEC("xdp")
int hyperion_filter(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;

    /* 1. Parse Ethernet */
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_PASS;

    /* Check for IPv4 (0x0800) */
    if (eth->h_proto != bpf_htons(ETH_P_IP)) return XDP_PASS;

    /* 2. Parse IPv4 */
    /* Math: Handle variable length headers safely */
    struct iphdr *ip = data + sizeof(struct ethhdr);
    if ((void *)(ip + 1) > data_end) return XDP_PASS;

    /* 3. Rate Limiter Logic */
    __u32 src_ip = ip->saddr;
    __u64 *packet_count;
    __u64 new_count = 1;

    packet_count = bpf_map_lookup_elem(&flow_tracker, &src_ip);
    
    if (packet_count) {
        /* Atomic increment for thread safety */
        __sync_fetch_and_add(packet_count, 1);
        new_count = *packet_count;
    } else {
        /* New session detected */
        bpf_map_update_elem(&flow_tracker, &src_ip, &new_count, BPF_ANY);
    }

    /* 4. Verdict: Drop if threshold exceeded */
    if (new_count > FLOOD_THRESHOLD) {
        if (new_count % 10 == 0) {
             const char fmt[] = "Hyperion M2: DROP -> Flood from IP: %x (Count: %llu)\n";
             bpf_trace_printk(fmt, sizeof(fmt), src_ip, new_count);
        }
        return XDP_DROP;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
