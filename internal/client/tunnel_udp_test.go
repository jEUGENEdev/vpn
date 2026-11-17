package client

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/jEUGENEdev/vpn/internal/model"
	tun "github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type udpReply struct {
	destination M.Socksaddr
	payload     string
}
type udpWriter struct{ replies chan udpReply }

func (w *udpWriter) WritePacket(b *buf.Buffer, destination M.Socksaddr) error {
	defer b.Release()
	w.replies <- udpReply{destination, string(b.Bytes())}
	return nil
}

// Exercise the actual sing-tun NAT and LineVPN packet handler. One unconnected
// application socket sends to multiple IPs AND multiple ports on the same IP.
func TestUDPSocketRoutesEveryDestination(t *testing.T) {
	c := testTrafficClient(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	source := M.SocksaddrFromNetIP(netip.MustParseAddrPort("172.29.255.1:49152"))
	var mu sync.Mutex
	owners := map[netip.AddrPort]int{}
	c.SetOwnerLookup(func(_ context.Context, network string, from, to netip.AddrPort) (model.ApplicationInfo, error) {
		mu.Lock()
		defer mu.Unlock()
		if network != "udp" || from != source.AddrPort() {
			t.Error("wrong original socket tuple")
		}
		owners[to]++
		return testApp("a"), nil
	})
	writer := &udpWriter{replies: make(chan udpReply, 16)}
	opts := c.stackOptions(ctx, nil, tun.Options{})
	nat := tun.NewUDPNat(tun.UDPNatOptions{
		Handler: opts.Handler, Timeout: opts.UDPTimeout, Mapping: opts.UDPMapping, Filtering: opts.UDPFiltering,
		Prepare: func(_, _ M.Socksaddr, _ any) (bool, context.Context, N.PacketWriter, N.CloseHandlerFunc) {
			return true, ctx, writer, nil
		},
	})
	if err := nat.Start(); err != nil {
		t.Fatal(err)
	}
	defer nat.Close()
	destinations := []M.Socksaddr{}
	for _, host := range []string{"127.0.0.1", "127.0.0.1", "127.0.0.2"} {
		echo, err := net.ListenPacket("udp", host+":0")
		if err != nil {
			t.Fatal(err)
		}
		defer echo.Close()
		destinations = append(destinations, M.SocksaddrFromNet(echo.LocalAddr()))
		go func() {
			payload := make([]byte, 65535)
			for {
				n, peer, err := echo.ReadFrom(payload)
				if err != nil {
					return
				}
				echo.WriteTo(payload[:n], peer)
			}
		}()
	}
	for _, destination := range destinations {
		nat.NewPacket([][]byte{[]byte(destination.String())}, source, destination, nil)
		select {
		case reply := <-writer.replies:
			if reply.destination != destination || reply.payload != destination.String() {
				t.Fatalf("misrouted reply: %+v", reply)
			}
		case <-time.After(3 * time.Second):
			t.Fatalf("lost UDP destination %v from same source socket", destination)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	for _, destination := range destinations {
		if owners[destination.AddrPort()] != 1 {
			t.Fatalf("destination bypassed owner/permission lookup: %v", destination)
		}
	}
}
