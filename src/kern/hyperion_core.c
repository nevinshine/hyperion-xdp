#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define MAX_RULES 2

struct policy_t {
    __u8 signature[8];
    __u8 sig_len;
    __u8 active;
    __u8 _pad[2]; 
};

struct event_t {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u32 action; 
    __u8 payload_snippet[8];
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct policy_t);
    __uint(max_entries, MAX_RULES);
} policy_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 14); 
} alert_ringbuf SEC(".maps");

struct cursor {
    void *pos;
    void *end;
};

SEC("xdp")
int hyperion_filter(struct xdp_md *ctx) {
    struct cursor c;
    c.pos = (void *)(long)ctx->data;
    c.end = (void *)(long)ctx->data_end;

    // 1. Ethernet
    struct ethhdr *eth = c.pos;
    if ((void *)(eth + 1) > c.end) return XDP_PASS;
    c.pos += sizeof(struct ethhdr);

    // 2. IP
    struct iphdr *ip = c.pos;
    if ((void *)(ip + 1) > c.end) return XDP_PASS;
    
    // VERIFIER FIX: Sanity check IP header length
    if (ip->ihl < 5) return XDP_PASS; 
    c.pos += ip->ihl * 4;

    if (ip->protocol != IPPROTO_TCP) return XDP_PASS;

    // 3. TCP
    struct tcphdr *tcp = c.pos;
    if ((void *)(tcp + 1) > c.end) return XDP_PASS;
    c.pos += tcp->doff * 4;
    
    // 4. Payload
    void *payload_start = c.pos;
    // VERIFIER FIX: Explicit pointer check instead of math
    if (payload_start >= c.end) return XDP_PASS;

    __u8 *data = (__u8 *)payload_start;

    // RULE LOOP
    #pragma unroll
    for (__u32 i = 0; i < MAX_RULES; i++) {
        __u32 key = i;
        struct policy_t *pol = bpf_map_lookup_elem(&policy_map, &key);
        
        if (!pol || pol->active == 0) continue;
        
        // VERIFIER FIX: Check bounds explicitly before reading signature
        // We need at least 4 bytes to check the first block
        if ((void*)(data + 4) > c.end) break; 

        // Now the verifier KNOWS data[0]..data[3] are safe
        if (data[0] == pol->signature[0] &&
            data[1] == pol->signature[1] &&
            data[2] == pol->signature[2] &&
            data[3] == pol->signature[3]) {
            
            // Found a match! Trigger Alert
            struct event_t *e = bpf_ringbuf_reserve(&alert_ringbuf, sizeof(*e), 0);
            if (e) {
                e->src_ip = ip->saddr;
                e->dst_ip = ip->daddr;
                e->src_port = tcp->source;
                e->dst_port = tcp->dest;
                e->action = 1; // DROP
                
                // Safe Copy for Alert Log
                #pragma unroll
                for (int k = 0; k < 8; k++) {
                    if ((void*)(data + k + 1) <= c.end)
                        e->payload_snippet[k] = data[k];
                    else
                        e->payload_snippet[k] = 0;
                }
                bpf_ringbuf_submit(e, 0);
            }
            return XDP_DROP;
        }
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";