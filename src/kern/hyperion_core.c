#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define MAX_RULES 2
#define MAX_DNS_NAME_LEN 64
#define MAX_DNS_LABELS 5

struct policy_t {
    __u8 signature[8];
    __u8 sig_len;
    __u8 active;
    __u8 _pad[2]; 
};

struct dnshdr {
    __be16 id;
    __be16 flags;
    __be16 qdcount;
    __be16 ancount;
    __be16 nscount;
    __be16 arcount;
};

struct dns_name_key {
    __u8 name[MAX_DNS_NAME_LEN];
};

// M5: New telemetry event structure
struct hyp_event {
    __u8 event_type;    // 0=ACCEPT, 1=DROP, 2=SIG_MATCH
    __u8 _pad1[3];      // Padding for alignment
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8 protocol;
    __u8 _pad2[7];      // Padding for 8-byte alignment before timestamp
    __u64 timestamp;
    char signature[8];  // matched signature (if any)
};

// M5: Flow tracking structures
struct flow_key {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8 protocol;
};

struct flow_value {
    __u64 packets;
    __u64 bytes;
    __u64 first_seen;
    __u64 last_seen;
};

// Legacy event structure (kept for compatibility)
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

// M4: IP Blocklist Map (Layer 2 drop)
// LRU_HASH prevents Map Exhaustion (E2BIG) by automatically evicting oldest
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, __u32);
    __type(value, __u8); // Flag/Dummy
    __uint(max_entries, 65536);
} blocklist_map SEC(".maps");

// M6: Layer 7 DNS Blocklist Map
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct dns_name_key);
    __type(value, __u8); // 1 = blocked
    __uint(max_entries, 10000);
} dns_blocklist_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 14); 
} alert_ringbuf SEC(".maps");

// M5: Ring buffer for telemetry events
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 16); // 64KB for telemetry
} telemetry_ringbuf SEC(".maps");

// M5: Flow tracking map
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, struct flow_key);
    __type(value, struct flow_value);
    __uint(max_entries, 10000);
} flow_map SEC(".maps");

struct cursor {
    void *pos;
    void *end;
};

static __attribute__((noinline)) void emit_telemetry(__u8 type, struct flow_key *fkey, __u8 *sig) {
    struct hyp_event *evt = bpf_ringbuf_reserve(&telemetry_ringbuf, sizeof(*evt), 0);
    if (!evt) return;
    evt->event_type = type;
    evt->src_ip = fkey->src_ip;
    evt->dst_ip = fkey->dst_ip;
    evt->src_port = fkey->src_port;
    evt->dst_port = fkey->dst_port;
    evt->protocol = fkey->protocol;
    evt->timestamp = bpf_ktime_get_ns();
    if (sig) {
        #pragma unroll
        for (int k = 0; k < 8; k++) evt->signature[k] = sig[k];
    } else {
        #pragma unroll
        for (int k = 0; k < 8; k++) evt->signature[k] = 0;
    }
    bpf_ringbuf_submit(evt, 0);
}

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

    // M5: Update flow tracking
    struct flow_key fkey = {};
    fkey.src_ip = ip->saddr;
    fkey.dst_ip = ip->daddr;
    fkey.protocol = ip->protocol;

    // M4: Layer 2 IP Blocklist check (O(1) Hash Map)
    __u32 src_ip = ip->saddr;
    __u8 *is_blocked = bpf_map_lookup_elem(&blocklist_map, &src_ip);
    if (is_blocked) {
        emit_telemetry(1, &fkey, NULL);
        return XDP_DROP;
    }

    if (ip->protocol == IPPROTO_TCP) {
        // 3. TCP
        struct tcphdr *tcp = c.pos;
        if ((void *)(tcp + 1) > c.end) return XDP_PASS;
        c.pos += tcp->doff * 4;
        fkey.src_port = tcp->source;
        fkey.dst_port = tcp->dest;
    } else if (ip->protocol == IPPROTO_UDP) {
        // 3. UDP
        struct udphdr *udp = c.pos;
        if ((void *)(udp + 1) > c.end) return XDP_PASS;
        c.pos += sizeof(struct udphdr);
        fkey.src_port = udp->source;
        fkey.dst_port = udp->dest;

        // M6: L7 DNS Payload Inspection
        // Parse DNS query on UDP port 53
        if (udp->dest == bpf_htons(53)) {
            struct dnshdr *dns = c.pos;
            if ((void *)(dns + 1) > c.end) return XDP_PASS; // Bound check DNS header
            c.pos += sizeof(struct dnshdr);
            
            __u8 *cursor = (__u8 *)c.pos;
            struct dns_name_key qname_key = {}; // Zero initialize key for verifier
            int name_idx = 0;
            
            #pragma unroll
            for (int i = 0; i < 3; i++) {
                if ((void *)(cursor + 1) > c.end) break;
                __u8 label_len = *cursor;
                
                if (name_idx < MAX_DNS_NAME_LEN - 1) {
                    qname_key.name[name_idx++] = label_len;
                }

                if (label_len == 0) {
                    // Reached end of QNAME, lookup in blocklist map
                    __u8 *blocked = bpf_map_lookup_elem(&dns_blocklist_map, &qname_key);
                    if (blocked && *blocked == 1) {
                        __u8 sig_snippet[8] = {0};
                        #pragma unroll
                        for (int k = 0; k < 8; k++) sig_snippet[k] = qname_key.name[k];
                        emit_telemetry(1, &fkey, sig_snippet);
                        return XDP_DROP;
                    }
                    break;
                }
                
                cursor++; // Move past length byte
                
                // Static verifier bound check: Ensure at least 15 bytes remain in the packet
                // to allow unconditional reading in the unrolled loop without branching explosion.
                if ((void *)(cursor + 15) > c.end) break;
                
                // Copy up to 15 characters linearly
                #pragma unroll
                for (int j = 0; j < 15; j++) { 
                    if (j < label_len && name_idx < MAX_DNS_NAME_LEN - 1) {
                        qname_key.name[name_idx++] = cursor[j];
                    }
                }
                
                // Safely advance the cursor by the true label length
                if ((void *)(cursor + label_len) > c.end) break;
                cursor += label_len;
            }
        }
    } else {
        return XDP_PASS;
    }
    
    __u64 now = bpf_ktime_get_ns();
    // Calculate packet length from data pointers
    void *data_start = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    __u32 pkt_len = data_end - data_start;
    
    struct flow_value *fval = bpf_map_lookup_elem(&flow_map, &fkey);
    if (fval) {
        // Update existing flow
        __sync_fetch_and_add(&fval->packets, 1);
        __sync_fetch_and_add(&fval->bytes, pkt_len);
        fval->last_seen = now;
    } else {
        // Create new flow entry
        struct flow_value new_fval = {};
        new_fval.packets = 1;
        new_fval.bytes = pkt_len;
        new_fval.first_seen = now;
        new_fval.last_seen = now;
        bpf_map_update_elem(&flow_map, &fkey, &new_fval, BPF_ANY);
    }
    
    // 4. Payload check for signature matching
    void *payload_start = c.pos;
    __u8 *data = (__u8 *)payload_start;
    int has_payload = (payload_start < c.end);
    
    // Only check for signature matches if we have payload data
    if (has_payload) {
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
                
                __u8 sig_snippet[8] = {0};
                #pragma unroll
                for (int k = 0; k < 8; k++) sig_snippet[k] = pol->signature[k];

                // M5: Emit SIG_MATCH and DROP telemetry events
                emit_telemetry(2, &fkey, sig_snippet);
                
                // Found a match! Trigger Alert (legacy)
                struct event_t *e = bpf_ringbuf_reserve(&alert_ringbuf, sizeof(*e), 0);
                if (e) {
                    e->src_ip = ip->saddr;
                    e->dst_ip = ip->daddr;
                    e->src_port = fkey.src_port;
                    e->dst_port = fkey.dst_port;
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
                
                emit_telemetry(1, &fkey, sig_snippet);
                return XDP_DROP;
            }
        }
    }

    // M5: Emit ACCEPT telemetry event for packets that pass
    emit_telemetry(0, &fkey, NULL);

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";