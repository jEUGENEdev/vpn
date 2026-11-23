package client

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"syscall"
	"testing"
	"time"

	"github.com/jEUGENEdev/vpn/internal/model"
	"github.com/jEUGENEdev/vpn/internal/transport"
	M "github.com/sagernet/sing/common/metadata"
)

// Exercise the real TCP handler and Xray outbound with an IPv6 tuple. Only
// the test VPN exit redirects to loopback; direct sockets are forbidden.
func TestIPv6TCPUsesSelectedVPNTunnel(t *testing.T) {
	for _, mode := range []string{"address", "application", "full-domain"} {
		t.Run(mode, func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			go func() {
				conn, err := listener.Accept()
				if err != nil {
					return
				}
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(3 * time.Second))
				io.Copy(conn, conn)
			}()
			c, err := New(t.TempDir(), &transport.Dialer{Control: func(string, string, syscall.RawConn) error {
				t.Error("protected IPv6 flow attempted a direct socket")
				return errors.New("forbidden")
			}})
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			c.ready = true
			app := testApp("a")
			c.apps[app.ID] = model.Application{ApplicationInfo: app, Decision: "addresses"}
			c.SetOwnerLookup(func(context.Context, string, netip.AddrPort, netip.AddrPort) (model.ApplicationInfo, error) {
				return app, nil
			})
			ip := netip.MustParseAddr("2a06:98c1:3101::ac40:9000")
			runtime := &c.vpn
			switch mode {
			case "address":
				c.config.Profile.Rules = []string{"2A06:98C1:3101:0:0:0:AC40:9000"}
			case "application":
				c.apps[app.ID] = model.Application{ApplicationInfo: app, Decision: "trusted"}
				c.config.Profile.AppUUID = "configured"
				runtime = &c.appVPN
			case "full-domain":
				c.config.TrafficMode = TrafficAll
				c.config.Profile.AppUUID = "configured"
				id, err := c.DNS.ID("example.com")
				if err != nil {
					t.Fatal(err)
				}
				ip = fake6(id)
				runtime = &c.appVPN
			}
			if err = runtime.Apply(map[string]any{"outbounds": []map[string]any{{"protocol": "freedom", "settings": map[string]any{"redirect": listener.Addr().String(), "finalRules": []map[string]any{{"action": "allow", "ip": []string{"127.0.0.1/32"}}}}}}}); err != nil {
				t.Fatal(err)
			}
			left, right := net.Pipe()
			defer right.Close()
			finished := make(chan error, 1)
			c.NewConnectionEx(context.Background(), left, M.SocksaddrFrom(netip.MustParseAddr("fd04:6c69:6e65:ffff::1"), 12345), M.SocksaddrFrom(ip, 443), func(err error) { finished <- err })
			right.SetDeadline(time.Now().Add(3 * time.Second))
			if _, err = right.Write([]byte("tunnel")); err != nil {
				t.Fatal(err)
			}
			response := make([]byte, 6)
			if _, err = io.ReadFull(right, response); err != nil || string(response) != "tunnel" {
				t.Fatal("IPv6 TCP did not reach the VPN outbound", string(response), err)
			}
			right.Close()
			select {
			case <-finished:
			case <-time.After(3 * time.Second):
				t.Fatal("IPv6 connection did not close")
			}
		})
	}
}
