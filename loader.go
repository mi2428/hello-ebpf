package main

import (
	"fmt"
	"log"
	"os"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/vishvananda/netlink"
)

const (
	ifaceName = "ens18" // 実際のネットワークインターフェースに置き換えてください
)

func main() {
	// コンパイル済みのeBPFプログラムをロード（encap.bpf.o）
	spec, err := ebpf.LoadCollectionSpec("encap.bpf.o")
	if err != nil {
		log.Fatalf("eBPFプログラムのロードに失敗しました: %v", err)
	}

	// カーネルにコレクションをロード
	objs := struct {
		XdpEncap *ebpf.Program `ebpf:"xdp_handle_gtp_encap"`
		TeidMap  *ebpf.Map     `ebpf:"teid_map"`
	}{}
	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		log.Fatalf("eBPFオブジェクトのロードと割り当てに失敗しました: %v", err)
	}
	defer objs.XdpEncap.Close()

	// インターフェース名からネットワークインターフェースを取得
	netIface, err := netlink.LinkByName(ifaceName) // 変数名を link から netIface に変更
	if err != nil {
		log.Fatalf("ネットワークインターフェース %s の取得に失敗しました: %v", ifaceName, err)
	}

	// XDPプログラムをネットワークインターフェースにアタッチ
	xdpLink, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpEncap,
		Interface: netIface.Attrs().Index,
		//Flags:     link.XDPGeneric, // XDPフラグ（Genericモード）
	})
	if err != nil {
		log.Fatalf("XDPプログラムのアタッチに失敗しました: %v", err)
	}
	defer xdpLink.Close()

	fmt.Println("XDPプログラムが正常にアタッチされました。終了するにはCtrl+Cを押してください。")
	<-make(chan os.Signal, 1)
}
