//go:build ignore

#include "bpf_endian.h"
#include "common.h"

char __license[] SEC("license") = "Dual MIT/GPL";

#define MAX_MAP_ENTRIES 16

#define GTPU_PORT 2152
#define GTPU_VERSION 0x30
#define GTPU_TYPE 0xff
#define MAX_TEID 65535

struct flow_info {
    __u32 teid;
};

struct gtpuhdr {
    __u8 flags;
    __u8 type;
    __u16 length;
    __u32 teid;
};

/* Define an LRU hash map for storing packet count by source IPv4 address */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_MAP_ENTRIES);
    __type(key, __u32); // source IPv4 address
    __type(value, struct flow_info);  // flow info containing TEID
} flow_map SEC(".maps");

static __u32 next_teid = 1;

static __always_inline __u32 generate_teid() {
    __u32 teid = next_teid;
    next_teid++;
    if (next_teid > MAX_TEID) {
        next_teid = 1;
    }
    return teid;
}

static __always_inline int encap_gtpu(struct xdp_md *ctx, __u32 teid) {
    // shift the ip header to make space for the gtp-u header (8 bytes)
    if (bpf_xdp_adjust_head(ctx, -8)) {
        return XDP_DROP;
    }

    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    struct iphdr *ip = (void *)(eth + 1);
    struct udphdr *udp = (void *)(ip + 1);

    // Parse the new GTP-U header (we just created space for it)
    struct gtpuhdr *gtp = (void *)(udp + 1);
    if ((void *)(gtp + 1) > data_end) {
        return XDP_DROP;
    }

    // Fill in the GTP-U header
    gtp->flags = GTPU_VERSION;    // GTPv1
    gtp->type = GTPU_TYPE;        // Type: G-PDU
    gtp->length = bpf_htons((__u16)(data_end - (void *)(gtp + 1)));
    gtp->teid = bpf_htonl(teid);  // Set TEID

    // Update the UDP length field
    udp->len = bpf_htons((__u16)(data_end - (void *)(udp + 1)));

    return XDP_PASS;
}

/*
Attempt to parse the IPv4 source address from the packet.
Returns 0 if there is no IPv4 header field; otherwise returns non-zero.
*/
static __always_inline int parse_ip_src_addr(struct xdp_md *ctx, __u32 *ip_src_addr) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;

    // First, parse the ethernet header.
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        return 0;
    }

    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        // The protocol is not IPv4, so we can't parse an IPv4 source address.
        return 0;
    }

    // Then parse the IP header.
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) {
        return 0;
    }

    // Return the source IP address in network byte order.
    *ip_src_addr = (__u32)(ip->saddr);
    return 1;
}

SEC("xdp")
int xdp_prog_func(struct xdp_md *ctx) {
    __u32 ip;
    if (!parse_ip_src_addr(ctx, &ip)) {
        // Not an IPv4 packet, so don't count it.
        goto done;
    }

    struct flow_info *flow = bpf_map_lookup_elem(&flow_map, &ip);
    if (!flow) {
        // No entry in the flow map for this IP address, so create a new flow.
        struct flow_info new_flow;
        new_flow.teid = generate_teid();
        bpf_map_update_elem(&flow_map, &ip, &new_flow, BPF_ANY);
        flow = &new_flow; // Use the newly created flow
    }

    // Encapsulate the packet with GTP-U and the TEID from the flow
    if (encap_gtpu(ctx, flow->teid) == XDP_DROP) {
        goto done;
    }

done:
    // Try changing this to XDP_DROP and see what happens!
    return XDP_PASS;
}
