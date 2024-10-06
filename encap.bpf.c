#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>  // bpf_htons, bpf_htonl を使うために必要

#define GTP_PORT 2152   // GTPv1-Uの標準ポート
#define UDP_PROTO 17    // IPPROTO_UDPの代わりに使用
#define GTP_TPDU 0xFF   // T-PDUのメッセージタイプ

// GTPv1-U ヘッダーの定義
struct gtpv1_hdr {
    __u8 flags;      // Version, Protocol Type, Reserved, Extension header flag
    __u8 msgtype;    // Message type
    __u16 length;    // Payload length (excluding GTPv1 header)
    __u32 teid;      // Tunnel Endpoint Identifier
};

// マップの定義：TEIDを保存するためのマップ
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 1024);
} teid_map SEC("maps");

// ヘルパー関数: UDPヘッダーをパースし、ペイロードのオフセットを取得
static __always_inline struct udphdr *parse_udp(void *data, __u64 nh_off, void *data_end) {
    struct udphdr *udp = data + nh_off;
    if ((void *)(udp + 1) > data_end) // 型の不一致を避けるためキャストを追加
        return NULL;
    return udp;
}

// ヘルパー関数: IPヘッダーをパース
static __always_inline struct iphdr *parse_ip(void *data, __u64 nh_off, void *data_end) {
    struct iphdr *ip = data + nh_off;
    if ((void *)(ip + 1) > data_end) // 型の不一致を避けるためキャストを追加
        return NULL;
    return ip;
}

// XDP プログラム: UDP パケットを GTPv1-U にカプセル化
SEC("xdp")
int xdp_handle_gtp_encap(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    __u64 nh_off = sizeof(struct ethhdr);

    struct iphdr *ip = parse_ip(data, nh_off, data_end);
    if (!ip || ip->protocol != UDP_PROTO)
        return XDP_PASS; // UDP 以外のパケットはそのまま通過

    nh_off += ip->ihl * 4;
    struct udphdr *udp = parse_udp(data, nh_off, data_end);
    if (!udp)
        return XDP_PASS;

    // GTPヘッダーを追加するためのスペースを確保
    if (bpf_xdp_adjust_head(ctx, -(int)sizeof(struct gtpv1_hdr)))
        return XDP_ABORTED;

    // ヘッダー調整後にポインタを再計算
    data = (void *)(long)ctx->data;
    data_end = (void *)(long)ctx->data_end;

    // GTPヘッダーを挿入
    struct gtpv1_hdr *gtp_hdr = data + sizeof(struct ethhdr) + ip->ihl * 4 + sizeof(struct udphdr);
    gtp_hdr->flags = 0x30;  // バージョン 1
    gtp_hdr->msgtype = GTP_TPDU; // T-PDU（データ転送）
    gtp_hdr->length = bpf_htons((__u16)(data_end - (void *)gtp_hdr - sizeof(struct gtpv1_hdr)));
    gtp_hdr->teid = bpf_htonl(0x12345678);  // 実際のTEIDロジックに置き換える

    // インターフェースインデックスを設定する
    int ifindex = 1;  // 適切なインターフェースインデックスに置き換える

    // パケットを次のインターフェースに転送
    return bpf_redirect(ifindex, 0);
}

char _license[] SEC("license") = "GPL";
