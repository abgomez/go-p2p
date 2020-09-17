package main

import (
	"context"
	"fmt"

	"github.com/libp2p/go-libp2p"
	crypto "github.com/libp2p/go-libp2p-core/crypto"
	"github.com/libp2p/go-libp2p-core/host"
	"github.com/multiformats/go-multiaddr"
)

func createPeer(prvKey crypto.PrivKey) (host.Host, error) {
	// 0.0.0.0 will listen on any interface device. Multiaddrs
	peerMultiAddr, _ := multiaddr.NewMultiaddr(fmt.Sprintf("/ip4/0.0.0.0/tcp/0"))

	// libp2p.New constructs a new libp2p Host.
	// Other options can be added here.
	node, err := libp2p.New(
		context.Background(),
		libp2p.ListenAddrs(peerMultiAddr),
		libp2p.Identity(prvKey),
	)
	if err != nil {
		return nil, err
	}

	return node, nil
}
