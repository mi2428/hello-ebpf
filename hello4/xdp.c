//go:build ignore

#include "bpf_endian.h"
#include "common.h"

char __license[] SEC("license") = "Dual MIT/GPL";

#define MAX_MAP_ENTRIES 16

#define GTPU_PORT 2152
#define GTPU_VERSION 0x30
#define GTPU_TYPE 0xff
#define MAX_TEID 65535

#define GTP_PEER_IP 0xC0A80164  // 192.168.1.100 in hex

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

static __always_inline int encap_gtpu(struct xdp_md *ctx, __u32 teid, __u32 ip_dst) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    struct iphdr *ip = (void *)(eth + 1);
    struct udphdr *udp = (void *)(ip + 1);

    // Calculate the size of the original IP packet
    __u32 ip_len = data_end - (void *)ip;

    // Adjust the head to make room for GTP-U and new outer UDP/IP headers (20+8+8=36 bytes)
    if (bpf_xdp_adjust_head(ctx, -(int)(sizeof(struct gtpuhdr) + sizeof(struct udphdr) + sizeof(struct iphdr)))) {
        return XDP_DROP;
    }

    // Recalculate the pointers after adjusting the head
    data = (void *)(long)ctx->data;
    data_end = (void *)(long)ctx->data_end;
    eth = data;
    ip = (void *)(eth + 1);
    udp = (void *)(ip + 1);

    // Ensure we don't access out of bounds
    struct gtpuhdr *gtp = (void *)(udp + 1);
    if ((void *)(gtp + 1) > data_end) {
        return XDP_DROP;
    }

    // Fill in the outer IP header (GTP encapsulating IP packet)
    ip->ihl = 5;
    ip->version = 4;
    ip->tot_len = bpf_htons(ip_len + sizeof(struct gtpuhdr) + sizeof(struct udphdr) + sizeof(struct iphdr));
    ip->protocol = IPPROTO_UDP;
    ip->saddr = bpf_htonl(0x0A0A0A0A);  // Replace with the appropriate local source IP (e.g., 10.10.10.10)
    ip->daddr = ip_dst;
    ip->ttl = 64;

    // Fill in the outer UDP header
    udp->source = bpf_htons(12345);  // Replace with appropriate source port
    udp->dest = bpf_htons(GTPU_PORT);
    udp->len = bpf_htons(ip_len + sizeof(struct gtpuhdr) + sizeof(struct udphdr));

    // Fill in the GTP-U header
    gtp->flags = GTPU_VERSION;    // GTPv1
    gtp->type = GTPU_TYPE;        // GTP-U PDU
    gtp->length = bpf_htons(ip_len);  // Length of the encapsulated IP packet
    gtp->teid = bpf_htonl(teid);  // TEID (Session ID)

    return XDP_TX;  // Transmit the packee
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

	if (ip->protocol != IPPROTO_UDP) {
		return 0;
	}

	// Then parse the UDP header.
	struct udphdr *udp = (void *)(ip + 1);
	if ((void *)(udp + 1) > data_end) {
		return 0;
	}

	// Here you can access the source and destination ports.
	__u16 src_port = bpf_ntohs(udp->source);
	__u16 dst_port = bpf_ntohs(udp->dest);

	if (dst_port != 453) {
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
        // Not an IPv4 packet, so don't process it.
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

    // Encapsulate the IP packet in GTP-U and send it to the GTP Peer
    if (encap_gtpu(ctx, flow->teid, GTP_PEER_IP) == XDP_DROP) {
        goto done;
    }

done:
    return XDP_PASS;
}