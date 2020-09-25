package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"
	"io"
	"log"
	random "math/rand"
	"os"
	"time"

	crypto "github.com/libp2p/go-libp2p-core/crypto"
	"github.com/libp2p/go-libp2p-core/host"
	"github.com/libp2p/go-libp2p-core/network"
	"github.com/libp2p/go-libp2p-core/peer"
	dht "github.com/libp2p/go-libp2p-kad-dht"
	pstore "github.com/libp2p/go-libp2p-peerstore"
	"github.com/libp2p/go-libp2p/p2p/discovery"
	"github.com/multiformats/go-multiaddr"
)

// var cfg = parseFlags()
var reader = rand.Reader

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

	// reader := rand.Reader
	prvKey, pubKey, err := crypto.GenerateKeyPairWithReader(crypto.RSA, 2048, reader)
	// prvKey, pubKey, err := crypto.GenerateKeyPairWithReader(crypto.Ed25519, 2048, r)
	// prvKey, pubKey, err := crypto.GenerateKeyPairWithReader(crypto.Secp256k1, 2048, r)
	// prvKey, pubKey, err := crypto.GenerateKeyPairWithReader(crypto.ECDSA, 2048, r)
	if err != nil {
		panic(err)
	}

	go readData(rw)
	go writeData(rw, prvKey, pubKey)

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

func writeData(rw *bufio.ReadWriter, prvKey crypto.PrivKey, pubKey crypto.PubKey) {
	message := []byte("message to be signed")
	hashed := sha256.Sum256(message)

	signature, err := prvKey.Sign(hashed[:])
	if err != nil {
		panic(err)
	}
	log.Printf("signature: %x\n", signature)

	_, err = pubKey.Verify(hashed[:], signature)
	if err != nil {
		panic(err)
	}

	for {
		// fmt.Print("> ")
		// sendData, err := stdReader.ReadString('\n')

		// if err != nil {
		// 	panic(err)
		// }

		// rw.WriteString(fmt.Sprintf("%s\n", sendData))
		//TODO ADD sensor and signing  mechanism
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

func getRSAkeys(src io.Reader, bits int) (*rsa.PrivateKey, error) {
	keys, err := rsa.GenerateKey(src, bits)
	if err != nil {
		return nil, err
	}
	return keys, nil
}

func main() {
	var kademliaDHT *dht.IpfsDHT

	ctx := context.Background()

	start := time.Now()
	// TODO: use PUF to create Deterministic keys
	// bs := make([]byte, 4)
	// binary.LittleEndian.PutUint32(bs, 31415926)
	// reader := bytes.NewReader(bs)
	// reader := rand.Reader
	// log.Printf("signature: %x\n", []byte(reader))

	// c := 10
	// b := make([]byte, c)
	// _, err := rand.Read(b)
	// if err != nil {
	// 	fmt.Println("error:", err)
	// 	return
	// }
	// // The slice should now contain random bytes instead of only zeroes.
	// fmt.Println(bytes.Equal(b, make([]byte, c)))
	// fmt.Println(b)

	// Create new key pair for this host.
	prvKey, pubKey, err := crypto.GenerateKeyPairWithReader(crypto.RSA, 2048, reader)
	// prvKey, pubKey, err := crypto.GenerateKeyPairWithReader(crypto.Ed25519, 2048, r)
	// prvKey, pubKey, err := crypto.GenerateKeyPairWithReader(crypto.Secp256k1, 2048, r)
	// prvKey, pubKey, err := crypto.GenerateKeyPairWithReader(crypto.ECDSA, 2048, r)
	if err != nil {
		panic(err)
	}
	log.Println("Time to generate peer ID: ", time.Since(start))

	// if cfg.CryptoType == "rsa" {
	// 	prvKey, pubKey, err := crypto.GenerateRSAKeyPair(2048, reader)
	// 	if err != nil {
	// 		panic(err)
	// 	}

	// 	signature, err := prvKey.Sign(hashed[:])
	// 	if err != nil {
	// 		panic(err)
	// 	}
	// 	log.Printf("RSA signature: %x\n", signature)

	// 	_, err = pubKey.Verify(hashed[:], signature)
	// 	if err != nil {
	// 		panic(err)
	// 	}
	// } else if cfg.CryptoType == "ed" {
	// 	prvKey, pubKey, err := crypto.GenerateEd25519Key(reader)
	// 	if err != nil {
	// 		panic(err)
	// 	}

	// 	signature, err := prvKey.Sign(hashed[:])
	// 	if err != nil {
	// 		panic(err)
	// 	}
	// 	log.Printf("Ed25519 signature: %x\n", signature)

	// 	_, err = pubKey.Verify(hashed[:], signature)
	// 	if err != nil {
	// 		panic(err)
	// 	}
	// } else if cfg.CryptoType == "sec" {
	// 	prvKey, pubKey, err := crypto.GenerateSecp256k1Key(reader)
	// 	if err != nil {
	// 		panic(err)
	// 	}

	// 	signature, err := prvKey.Sign(hashed[:])
	// 	if err != nil {
	// 		panic(err)
	// 	}
	// 	log.Printf("Secp256k1 signature: %x\n", signature)

	// 	_, err = pubKey.Verify(hashed[:], signature)
	// 	if err != nil {
	// 		panic(err)
	// 	}
	// } else if cfg.CryptoType == "ecd" {
	// 	prvKey, pubKey, err := crypto.GenerateECDSAKeyPair(reader)
	// 	if err != nil {
	// 		panic(err)
	// 	}

	// 	signature, err := prvKey.Sign(hashed[:])
	// 	if err != nil {
	// 		panic(err)
	// 	}
	// 	log.Printf("ECDSA signature: %x\n", signature)

	// 	_, err = pubKey.Verify(hashed[:], signature)
	// 	if err != nil {
	// 		panic(err)
	// 	}
	// }

	// Create new peer
	node, err := createPeer(prvKey)
	if err != nil {
		panic(err)
	}

	log.Printf("size of ID: %d", node.ID().Size())

	// Start a DHT, for use in peer discovery. We can't just make a new DHT
	// client because we want each peer to maintain its own local copy of the DHT
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
			go writeData(rw, prvKey, pubKey)
			go readData(rw)
		}
	}

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
