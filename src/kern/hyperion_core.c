#include "vmlinux.h" /* All kernel types in one file */
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/* Standard XDP Return Codes */
#define XDP_PASS 2
#define XDP_DROP 1

/* Ethernet Protocol ID for IPv4 */
#define ETH_P_IP 0x0800

SEC("xdp")
int hyperion_filter(struct xdp_md *ctx) {
    /* 1. Setup Pointers to Packet Data */
    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;

    /* 2. Parse Ethernet Header */
    struct ethhdr *eth = data;
    /* Boundary Check: Does the packet actually have an Ethernet header? */
    if ((void *)(eth + 1) > data_end) {
        return XDP_PASS;
    }

    /* 3. Filter: Only look at IPv4 traffic */
    if (bpf_ntohs(eth->h_proto) != ETH_P_IP) {
        return XDP_PASS;
    }

    /* 4. Parse IPv4 Header */
    /* Math: Jump over the Ethernet header to find the IP header */
    struct iphdr *ip = data + sizeof(struct ethhdr);
    /* Boundary Check */
    if ((void *)(ip + 1) > data_end) {
        return XDP_PASS;
    }

    /* 5. RESEARCH LOGIC: Drop specific IP (1.2.3.4) */
    /* 1.2.3.4 in Hex Little Endian is 0x04030201 */
    if (ip->daddr == 0x04030201) {
        bpf_printk("Hyperion: KILL -> Dest 1.2.3.4 detected!\n");
        return XDP_DROP;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
