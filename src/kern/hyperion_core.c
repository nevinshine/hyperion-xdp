/* HYPERION M3.0: Deep Packet Inspection (DPI) */
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>  /* Added for M3: TCP Header parsing */
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/* Map definitions */
#define XDP_PASS 2
#define XDP_DROP 1

/* CONFIG: DPI Scanner */
#define MAX_SCAN_LEN 64
#define SIG_LEN 4
/* Signature: "hack" (hex: 68 61 63 6b) */
static const char SIGNATURE[SIG_LEN] = {'h', 'a', 'c', 'k'};

/* * M3 ARCHITECTURE: Stateless DPI
 * We removed the Flow State Table (LRU_HASH) for this milestone
 * to focus purely on O(N) payload analysis.
 */

SEC("xdp")
int hyperion_filter(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;

    /* 1. Parse Ethernet */
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_PASS;

    /* Check for IPv4 */
    if (eth->h_proto != bpf_htons(ETH_P_IP)) return XDP_PASS;

    /* 2. Parse IPv4 */
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) return XDP_PASS;

    /* * MATH: Calculate variable IP Header Length
     * ip->ihl is in 32-bit words, so * 4 to get bytes.
     */
    int ip_len = ip->ihl * 4;
    if (ip_len < sizeof(struct iphdr)) return XDP_PASS;

    /* 3. Parse TCP (M3 Requirement) */
    if (ip->protocol != IPPROTO_TCP) return XDP_PASS;

    /* * MATH: Pointer Arithmetic to find TCP Header
     * (Start of IP) + (IP Header Length) = (Start of TCP)
     */
    struct tcphdr *tcp = (void *)ip + ip_len;
    if ((void *)(tcp + 1) > data_end) return XDP_PASS;

    /* 4. Find Payload Logic */
    int tcp_len = tcp->doff * 4;
    void *payload = (void *)tcp + tcp_len;

    /* 5. Deep Packet Inspection Loop */
    if (payload < data_end) {
        unsigned char *byte_ptr = payload;

        /* * UNROLLED LOOP: Scan the first 64 bytes
         * We verify every byte access against data_end to satisfy the verifier.
         */
        #pragma unroll
        for (int i = 0; i < MAX_SCAN_LEN; i++) {
            /* Boundary Check: Don't read past the packet end */
            if (byte_ptr + i + SIG_LEN > (unsigned char *)data_end) break;

            /* Signature Matching: "hack" */
            if (byte_ptr[i]     == SIGNATURE[0] &&
                byte_ptr[i + 1] == SIGNATURE[1] &&
                byte_ptr[i + 2] == SIGNATURE[2] &&
                byte_ptr[i + 3] == SIGNATURE[3]) {

                /* VERDICT: DROP immediately on signature match */
                const char fmt[] = "Hyperion M3: DROP -> Malicious Payload detected in packet\n";
                bpf_trace_printk(fmt, sizeof(fmt));
                return XDP_DROP;
            }
        }
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";