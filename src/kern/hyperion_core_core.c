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

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, __u32);
    __type(value, __u8); // 1 = blocked
    __uint(max_entries, 65536);
} blocklist_map SEC(".maps");

struct port_key {
    __u8 protocol;
    __u8 pad;
    __u16 port;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct port_key);
    __type(value, __u8); // 1 = redirect
    __uint(max_entries, 1024);
} redirect_ports_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_XSKMAP);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 64);
} xsk_map SEC(".maps");

struct hyp_event {
    __u8 event_type;    // 1=DROP
    __u8 _pad1[3];
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8 protocol;
    __u8 _pad2[7];
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

static __attribute__((noinline)) void emit_drop_telemetry(__u32 sip, __u32 dip, __u16 sport, __u16 dport, __u8 proto) {
    struct hyp_event *evt = bpf_ringbuf_reserve(&telemetry_ringbuf, sizeof(*evt), 0);
    if (!evt) return;
    evt->event_type = 1; // DROP
    evt->src_ip = sip;
    evt->dst_ip = dip;
    evt->src_port = sport;
    evt->dst_port = dport;
    evt->protocol = proto;
    evt->timestamp = bpf_ktime_get_ns();
    bpf_ringbuf_submit(evt, 0);
}

SEC("xdp")
int hyperion_filter(struct xdp_md *ctx) {
    struct cursor c;
    c.pos = (void *)(long)ctx->data;
    c.end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = c.pos;
    if ((void *)(eth + 1) > c.end) return XDP_PASS;
    c.pos += sizeof(struct ethhdr);

    if (eth->h_proto != bpf_htons(ETH_P_IP)) return XDP_PASS;

    struct iphdr *ip = c.pos;
    if ((void *)(ip + 1) > c.end) return XDP_PASS;
    
    if (ip->ihl < 5) return XDP_PASS; 
    c.pos += ip->ihl * 4;

    __u32 src_ip = ip->saddr;
    __u32 dst_ip = ip->daddr;
    __u8 protocol = ip->protocol;

    __u8 *is_blocked = bpf_map_lookup_elem(&blocklist_map, &src_ip);
    if (is_blocked && *is_blocked == 1) {
        emit_drop_telemetry(src_ip, dst_ip, 0, 0, protocol);
        return XDP_DROP;
    }

    __u16 src_port = 0;
    __u16 dst_port = 0;

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

    struct port_key pkey = {};
    pkey.protocol = protocol;
    pkey.port = bpf_ntohs(dst_port); 

    __u8 *should_redirect = bpf_map_lookup_elem(&redirect_ports_map, &pkey);
    if (should_redirect && *should_redirect == 1) {
        __u32 *xsk = bpf_map_lookup_elem(&xsk_map, &ctx->rx_queue_index);
        if (!xsk) {
            struct hyp_event *evt = bpf_ringbuf_reserve(&telemetry_ringbuf, sizeof(*evt), 0);
            if (evt) {
                evt->event_type = 3; 
                evt->src_ip = src_ip;
                evt->dst_ip = dst_ip;
                evt->src_port = bpf_ntohs(src_port);
                evt->dst_port = bpf_ntohs(dst_port);
                evt->protocol = protocol;
                evt->timestamp = bpf_ktime_get_ns();
                bpf_ringbuf_submit(evt, 0);
            }
            return XDP_PASS;
        }
        
        return bpf_redirect_map(&xsk_map, ctx->rx_queue_index, XDP_PASS);
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
