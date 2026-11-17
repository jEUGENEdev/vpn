package client

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/jEUGENEdev/vpn/internal/model"
	tun "github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type udpMediaReply struct {
	from M.Socksaddr
	data string
}
type udpTestWriter chan udpMediaReply

func (w udpTestWriter) WritePacket(b *buf.Buffer, from M.Socksaddr) error {
	defer b.Release()
	w <- udpMediaReply{from, string(b.Bytes())}
	return nil
}

// Exercise the actual sing-tun NAT and Client packet handler. A single media
// socket sends to several peers; every peer must be observed and answered.
func TestUDPMediaSocketTracksEveryDestination(t *testing.T) {
	for _, host := range []string{"127.0.0.1", "::1"} {
		t.Run(host, func(t *testing.T) {
			c := testTrafficClient(t)
			app := testApp("a")
			lookups := make(chan netip.AddrPort, 3)
			c.SetOwnerLookup(func(_ context.Context, network string, source, dest netip.AddrPort) (model.ApplicationInfo, error) {
				if network != "udp" || source.Port() != 42000 {
					return model.ApplicationInfo{}, fmt.Errorf("wrong captured tuple")
				}
				lookups <- dest
				return app, nil
			})
			replies := make(udpTestWriter, 12)
			options := c.stackOptions(context.Background(), nil, tun.Options{})
			nat := tun.NewUDPNat(tun.UDPNatOptions{Handler: c, Shared: true,
				Timeout: options.UDPTimeout, Mapping: options.UDPMapping, Filtering: options.UDPFiltering,
				Prepare: func(_, _ M.Socksaddr, _ any) (bool, context.Context, N.PacketWriter, N.CloseHandlerFunc) {
					return true, context.Background(), replies, nil
				}})
			if err := nat.Start(); err != nil {
				t.Fatal(err)
			}
			defer nat.Close()
			source := M.Socksaddr{Addr: netip.MustParseAddr(host), Port: 42000}
			peers := make([]M.Socksaddr, 0, 3)
			for i := 0; i < 3; i++ {
				address := net.JoinHostPort(host, "0")
				if i == 2 && host == "127.0.0.1" {
					address = net.JoinHostPort("127.0.0.2", fmt.Sprint(peers[0].Port))
				}
				echo, err := net.ListenPacket("udp", address)
				if err != nil {
					t.Fatal(err)
				}
				defer echo.Close()
				go func() {
					b := make([]byte, 65535)
					for {
						n, from, err := echo.ReadFrom(b)
						if err != nil {
							return
						}
						echo.WriteTo(b[:n], from)
					}
				}()
				peers = append(peers, M.SocksaddrFromNet(echo.LocalAddr()))
			}
			for round := 0; round < 2; round++ {
				want := map[M.Socksaddr]string{}
				for i, dest := range peers {
					payload := fmt.Sprintf("media-%d-%d", round, i)
					want[dest] = payload
					nat.NewPacket([][]byte{[]byte(payload)}, source, dest, nil)
				}
				deadline := time.NewTimer(3 * time.Second)
				for len(want) > 0 {
					select {
					case reply := <-replies:
						if want[reply.from] != reply.data {
							t.Fatalf("wrong media peer or packet: %+v", reply)
						}
						delete(want, reply.from)
					case <-deadline.C:
						t.Fatalf("media destinations were dropped before routing: %v", want)
					}
				}
				deadline.Stop()
			}
			seen := map[netip.AddrPort]bool{}
			for range peers {
				select {
				case dest := <-lookups:
					seen[dest] = true
				default:
					t.Fatal("a media endpoint bypassed owner lookup")
				}
			}
			if len(seen) != len(peers) {
				t.Fatal("destinations shared a permission decision", seen)
			}
			c.mu.RLock()
			defer c.mu.RUnlock()
			for _, peer := range peers {
				if c.observed[peer.Addr.String()].Sources[app.ID].ID != app.ID {
					t.Fatal("missing media application attribution")
				}
			}
		})
	}
}
