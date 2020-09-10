package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"flag"
	"fmt"
	"log"
	random "math/rand"
	"os"
	"time"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p-core/host"
	"github.com/libp2p/go-libp2p-core/network"
	"github.com/libp2p/go-libp2p-core/peer"
	crypto "github.com/libp2p/go-libp2p-crypto"
	dht "github.com/libp2p/go-libp2p-kad-dht"
	pstore "github.com/libp2p/go-libp2p-peerstore"
	"github.com/libp2p/go-libp2p/p2p/discovery"
	"github.com/multiformats/go-multiaddr"
)

type discoveryNotifee struct {
	host host.Host
}

func (rh *discoveryNotifee) HandlePeerFound(pi pstore.PeerInfo) {
	// Connect will add the host to the peerstore and dial up a new connection
	// fmt.Println(fmt.Sprintf("\nhost %v connecting to %v... (blocking)", rh.host.ID(), pi.ID))

	err := rh.host.Connect(context.Background(), pi)
	if err != nil {
		fmt.Println(fmt.Sprintf("Error when connecting peers: %v", err))
		return
	}
}

func handleStream(stream network.Stream) {
	fmt.Println("Got a new stream!")

	// Create a buffer stream for non blocking read and write.
	rw := bufio.NewReadWriter(bufio.NewReader(stream), bufio.NewWriter(stream))

	go readData(rw)
	go writeData(rw)

	// 'stream' will stay open until you close it (or the other side closes it).
}

func readData(rw *bufio.ReadWriter) {
	for {
		str, _ := rw.ReadString('\n')

		if str == "" {
			return
		}
		if str != "\n" {
			// Green console colour: 	\x1b[32m
			// Reset console colour: 	\x1b[0m
			fmt.Printf("\x1b[32m%s\x1b[0m> ", str)
		}

	}
}

func writeData(rw *bufio.ReadWriter) {
	// stdReader := bufio.NewReader(os.Stdin)

	for {
		// fmt.Print("> ")
		// sendData, err := stdReader.ReadString('\n')

		// if err != nil {
		// 	panic(err)
		// }

		// rw.WriteString(fmt.Sprintf("%s\n", sendData))
		location := fmt.Sprint(random.Intn(9999)) + "," + fmt.Sprint(random.Intn(9999))
		rw.WriteString(fmt.Sprintf("%s\n", location))
		rw.Flush()
		time.Sleep(time.Second * 10)
	}
}

func peerInfo(node host.Host) {

	peerAddr, _ := multiaddr.NewMultiaddr(fmt.Sprintf("/ipfs/%s", node.ID().Pretty()))
	addr := node.Addrs()[0]
	fullAddr := addr.Encapsulate(peerAddr)

	log.Printf("Peer ID: %s", node.ID())
	log.Printf("Peer Addr: %s", node.Addrs())
	log.Printf("MultiAddrs: %s\n", fullAddr)
	// fmt.Println("Peerstore: ", peer.Peerstore())
}

func dhtInfo(node peer.ID, dhts *dht.IpfsDHT) {
	fmt.Println("this is the info of the dht table")
	fmt.Println(dhts.PeerID())
	fmt.Println(dhts.FindPeer(context.Background(), node))
}

func main() {
	var kademliaDHT *dht.IpfsDHT

	help := flag.Bool("help", false, "Display Help")
	// cfg := parseFlags()

	if *help {
		fmt.Printf("Simple example for peer discovery using mDNS. mDNS is great when you have multiple peers in local LAN.")
		fmt.Println("Usage: ./peer")
		os.Exit(0)
	}

	ctx := context.Background()
	r := rand.Reader

	// Creates a new RSA key pair for this host. TODO: use PUF to create dynamic keys
	prvKey, _, err := crypto.GenerateKeyPairWithReader(crypto.RSA, 2048, r)
	if err != nil {
		panic(err)
	}

	// 0.0.0.0 will listen on any interface device. Multiaddrs
	peerMultiAddr, _ := multiaddr.NewMultiaddr(fmt.Sprintf("/ip4/127.0.0.1/tcp/0"))

	// libp2p.New constructs a new libp2p Host.
	// Other options can be added here.
	node, err := libp2p.New(
		ctx,
		libp2p.ListenAddrs(peerMultiAddr),
		libp2p.Identity(prvKey),
	)
	if err != nil {
		panic(err)
	}

	// Start a DHT, for use in peer discovery. We can't just make a new DHT
	// client because we want each peer to maintain its own local copy of the
	// DHT, so that the bootstrapping node of the DHT can go down without
	// inhibiting future peer discovery.
	kademliaDHT, err = dht.New(ctx, node)
	if err != nil {
		panic(err)
	}

	// Set a function as stream handler.
	// This function is called when a peer initiates a connection and starts a stream with this peer.
	log.Printf("Set Stream Handler with protocol gps\n")
	node.SetStreamHandler("/gps/1.0", handleStream)

	// Set mdns service
	log.Printf("Start discovery service\n")
	discoveryService, err := discovery.NewMdnsService(ctx, node, time.Second, "meetme")
	if err != nil {
		log.Fatal(err)
	}
	defer discoveryService.Close()

	nodeHandler := &discoveryNotifee{node}
	discoveryService.RegisterNotifee(nodeHandler)

	time.Sleep(time.Second * 5)
	store := node.Peerstore()

	// Say hello to your friends
	log.Printf("Peers in peerstore\n")
	log.Println(store.Peers())
	for _, p := range store.Peers()[1:] {
		if p.Pretty() != node.ID().Pretty() {
			fmt.Printf("Connecting to: %v -- ", p.Pretty())
			stream, err := node.NewStream(ctx, p, "/gps/1.0")
			if err != nil {
				panic(err)
			}

			// Create a buffered stream so that read and writes are non blocking.
			rw := bufio.NewReadWriter(bufio.NewReader(stream), bufio.NewWriter(stream))

			// Create a thread to read and write data.
			go writeData(rw)
			go readData(rw)
		}
	}

	// select {}

	// peerChan := initMDNS(ctx, node, cfg.RendezvousString)

	// select {
	// case peer := <-initMDNS(ctx, node, cfg.RendezvousString):
	// 	fmt.Println("Found peer:", peer, ", connecting")
	// 	fmt.Println(kademliaDHT.FindPeer(ctx, peer.ID))
	// default:
	// 	fmt.Println("No peer Found")
	// }

	// peer := <-peerChan // will block untill we discover a peer
	// fmt.Println("Found peer:", peer, ", connecting")

	for {
		reader := bufio.NewReader(os.Stdin)
		fmt.Println("hey..")
		option, _ := reader.ReadString('\n')
		if option == "peer\n" {
			peerInfo(node)
		} else {
			for _, p := range store.Peers()[1:] {
				if p.Pretty() != node.ID().Pretty() {
					dhtInfo(p, kademliaDHT)
				}
				break
			}
		}
	}
}
