package client

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"syscall"
	"testing"
	"time"

	"github.com/jEUGENEdev/vpn/internal/model"
	"github.com/jEUGENEdev/vpn/internal/policy"
	tun "github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type udpReply struct {
	destination M.Socksaddr
	payload     string
}
type udpReplies chan udpReply

func (r udpReplies) WritePacket(b *buf.Buffer, destination M.Socksaddr) error {
	defer b.Release()
	r <- udpReply{destination, string(b.Bytes())}
	return nil
}

// Exercise the real NAT service with the production stack options and client
// handler: one local UDP socket, three peers, mixed direct and approved routes.
func TestUDPSocketRoutesAndObservesEveryDestination(t *testing.T) {
	c := testTrafficClient(t)
	c.ready = true
	c.config.Profile.Rules = []string{"127.0.0.2"}
	if err := c.vpn.Apply(map[string]any{"outbounds": []map[string]any{{"protocol": "freedom", "settings": map[string]any{"finalRules": []map[string]any{{"action": "allow", "ip": []string{"127.0.0.2/32"}}}}}}}); err != nil {
		t.Fatal(err)
	}
	c.Direct.Control = func(network, address string, raw syscall.RawConn) error {
		host, _, _ := net.SplitHostPort(address)
		if host == "127.0.0.2" {
			return errors.New("approved peer must never use direct dialer")
		}
		return nil
	}
	lookups := make(chan netip.AddrPort, 8)
	app := testApp("a")
	c.SetOwnerLookup(func(ctx context.Context, network string, source, dest netip.AddrPort) (model.ApplicationInfo, error) {
		lookups <- dest
		return app, nil
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	options := c.stackOptions(ctx, nil, tun.Options{})
	replies := make(udpReplies, 8)
	nat := tun.NewUDPNat(tun.UDPNatOptions{Handler: c, Timeout: options.UDPTimeout, Mapping: options.UDPMapping, Filtering: options.UDPFiltering,
		Prepare: func(source, dest M.Socksaddr, data any) (bool, context.Context, N.PacketWriter, N.CloseHandlerFunc) {
			return true, ctx, replies, nil
		},
	})
	if err := nat.Start(); err != nil {
		t.Fatal(err)
	}
	defer nat.Close()
	source := M.SocksaddrFrom(netip.MustParseAddr("172.29.255.1"), 40000)
	for _, host := range []string{"127.0.0.1", "127.0.0.1", "127.0.0.2"} {
		echo, err := net.ListenPacket("udp", net.JoinHostPort(host, "0"))
		if err != nil {
			t.Fatal(err)
		}
		defer echo.Close()
		go func() {
			b := make([]byte, 2048)
			for {
				n, peer, err := echo.ReadFrom(b)
				if err != nil {
					return
				}
				echo.WriteTo(b[:n], peer)
			}
		}()
		dest := M.SocksaddrFromNet(echo.LocalAddr())
		nat.NewPacket([][]byte{[]byte("media")}, source, dest, nil)
		select {
		case reply := <-replies:
			if reply.destination != dest || reply.payload != "media" {
				t.Fatal(reply)
			}
		case <-time.After(3 * time.Second):
			t.Fatalf("UDP peer %s was dropped before routing", dest)
		}
		select {
		case looked := <-lookups:
			if looked != dest.AddrPort() {
				t.Fatal("wrong socket owner tuple", looked)
			}
		case <-time.After(time.Second):
			t.Fatal("destination bypassed application attribution")
		}
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	if len(c.active) != 3 || len(c.observed) != 2 {
		t.Fatal("missing UDP flows or observations", c.active, c.observed)
	}
	for _, flow := range c.active {
		want := policy.Direct
		if flow.Target == "127.0.0.2" {
			want = policy.VPN
		}
		if flow.Route != want || flow.AppID != app.ID {
			t.Fatal("wrong peer policy", flow)
		}
	}
}
