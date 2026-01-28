/* HYPERION M4.6: Dynamic Policy & Telemetry (Stable) */
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define XDP_PASS 2
#define XDP_DROP 1

/* STABILITY CONFIG: Tuned to pass BPF Verifier on 5.4+ Kernels */
#define MAX_SCAN_LEN 32   /* Scan first 32 bytes of payload */
#define MAX_SIG_LEN 8     /* Max length per signature */
#define MAX_RULES 5       /* Capacity of Policy Map */

struct policy_t {
    unsigned char signature[MAX_SIG_LEN];
    __u32 sig_len;
    __u32 active;
};

struct alert_event_t {
    __u32 src_ip;
    __u32 dst_ip;
    unsigned char payload_snippet[8];
    __u32 rule_id;
};

/* MAP: Dynamic Policy Storage */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct policy_t);
    __uint(max_entries, MAX_RULES);
} policy_map SEC(".maps");

/* MAP: High-Speed Telemetry */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24); // 16MB Ring Buffer
} alert_ringbuf SEC(".maps");

SEC("xdp")
int hyperion_filter(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;

    // --- 1. Header Parsing ---
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP)) return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) return XDP_PASS;
    if (ip->protocol != IPPROTO_TCP) return XDP_PASS;

    struct tcphdr *tcp = (void *)ip + (ip->ihl * 4);
    if ((void *)(tcp + 1) > data_end) return XDP_PASS;
    
    void *payload = (void *)tcp + (tcp->doff * 4);

    // --- 2. Multi-Signature Scanning ---
    if (payload < data_end) {
        unsigned char *payload_start = payload;
        
        // Loop through all enabled policies
        #pragma unroll
        for (int rule_idx = 0; rule_idx < MAX_RULES; rule_idx++) {
            __u32 key = rule_idx;
            struct policy_t *policy = bpf_map_lookup_elem(&policy_map, &key);
            
            // Skip invalid rules
            if (!policy || policy->active != 1) continue;
            if (policy->sig_len == 0 || policy->sig_len > MAX_SIG_LEN) continue;

            // Scan the payload window
            #pragma unroll
            for (int i = 0; i < MAX_SCAN_LEN; i++) {
                // Safety: End of Packet
                if (payload_start + i + 1 > (unsigned char *)data_end) break;

                int match = 1;
                // Compare bytes
                #pragma unroll
                for (int j = 0; j < MAX_SIG_LEN; j++) {
                    // Safety: End of Signature or Packet
                    if (j >= policy->sig_len) break;
                    if (payload_start + i + j + 1 > (unsigned char *)data_end) {
                        match = 0; break;
                    }
                    if (payload_start[i+j] != policy->signature[j]) {
                        match = 0; break;
                    }
                }

                if (match) {
                    // --- MATCH: Alert & Drop ---
                    struct alert_event_t *event;
                    event = bpf_ringbuf_reserve(&alert_ringbuf, sizeof(*event), 0);
                    if (event) {
                        event->src_ip = ip->saddr;
                        event->dst_ip = ip->daddr;
                        event->rule_id = rule_idx;
                        #pragma unroll
                        for(int k=0; k<8; k++) {
                            if (payload_start + i + k < (unsigned char*)data_end)
                                event->payload_snippet[k] = payload_start[i+k];
                            else
                                event->payload_snippet[k] = 0;
                        }
                        bpf_ringbuf_submit(event, 0);
                    }
                    return XDP_DROP;
                }
            }
        }
    }
    return XDP_PASS;
}
char _license[] SEC("license") = "GPL";
