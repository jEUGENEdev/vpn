package client

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/jEUGENEdev/vpn/internal/model"
	"github.com/jEUGENEdev/vpn/internal/policy"
	"github.com/jEUGENEdev/vpn/internal/secure"
	"github.com/jEUGENEdev/vpn/internal/store"
	"github.com/jEUGENEdev/vpn/internal/transport"
	M "github.com/sagernet/sing/common/metadata"
)

// Join the selective application decision, original IPv6 tuple and both real
// VLESS credentials in one test. The success case uses an actual IPv6 socket;
// the public-address failure case is stopped before connect(), never sent out.
func TestSelectiveIPv6RealTunnelAndEgressFailure(t *testing.T) {
	for _, egress := range []string{"round-trip", "exit-unreachable", "exit-recovery"} {
		for _, decision := range []string{"addresses", "trusted"} {
			t.Run(decision+"/"+egress, func(t *testing.T) {
				egressFailure := egress == "exit-unreachable"
				tlsTarget := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					_, _ = w.Write([]byte("local reality target"))
				}))
				tlsTarget.TLS = &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13}
				tlsTarget.EnableHTTP2 = true
				tlsTarget.StartTLS()
				t.Cleanup(tlsTarget.Close)
				echo, err := net.Listen("tcp6", "[::1]:0")
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { echo.Close() })
				go func() {
					for {
						conn, err := echo.Accept()
						if err != nil {
							return
						}
						go func() {
							defer conn.Close()
							conn.SetDeadline(time.Now().Add(5 * time.Second))
							io.Copy(conn, conn)
						}()
					}
				}()
				destination := echo.Addr().(*net.TCPAddr).AddrPort()
				if egressFailure {
					// A public-format fixture, never the user's destination.
					destination = netip.MustParseAddrPort("[2606:4700:4700::1111]:443")
				}
				var exitAttempts, directAttempts atomic.Int32
				var temporarilyUnreachable atomic.Bool
				temporarilyUnreachable.Store(egress == "exit-recovery")
				transport.InstallDialer(&transport.Dialer{Control: func(network, address string, _ syscall.RawConn) error {
					endpoint, err := netip.ParseAddrPort(address)
					if err != nil {
						return err
					}
					if endpoint == destination && network == "tcp6" && temporarilyUnreachable.Load() {
						exitAttempts.Add(1)
						return syscall.ENETUNREACH
					}
					// Only test-local REALITY and echo sockets may connect.
					if endpoint.Addr().IsLoopback() {
						return nil
					}
					if egressFailure && endpoint == destination && network == "tcp6" && policy.Public(endpoint.Addr()) {
						exitAttempts.Add(1)
						return syscall.ENETUNREACH
					}
					t.Errorf("unexpected non-local socket: %s %s", network, address)
					return errors.New("test prohibits external traffic")
				}})
				t.Cleanup(func() { transport.InstallDialer(&transport.Dialer{}) })
				free, err := net.Listen("tcp4", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				port := free.Addr().(*net.TCPAddr).Port
				free.Close()
				key, err := ecdh.X25519().GenerateKey(rand.Reader)
				if err != nil {
					t.Fatal(err)
				}
				options := transport.ServerOptions{Listen: "127.0.0.1", Port: port,
					PrivateKey: base64.RawURLEncoding.EncodeToString(key.Bytes()), PublicKey: base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes()),
					SNI: "example.com", Target: tlsTarget.Listener.Addr().String(), ShortID: "12ab34cd", Path: "/selective-ipv6-test"}
				st := store.Empty()
				rules := []string{}
				if decision == "addresses" {
					// Exercise equivalent expanded and compressed IPv6 spellings.
					rules = []string{destination.Addr().StringExpanded()}
				}
				st.Accounts["a"] = store.Account{Account: model.Account{ID: "a", Status: "active", Rules: rules}}
				device := store.Device{Device: model.Device{ID: "d", AccountID: "a", Expires: time.Now().Add(time.Hour)}, Secret: secure.UUID(), AppSecret: secure.UUID()}
				st.Devices["d"] = device
				cfg := transport.ServerConfig(st, options, time.Now())
				if !egressFailure {
					// Production still forbids loopback; only this local fixture allows it.
					cfg["outbounds"].([]map[string]any)[1]["settings"] = map[string]any{"finalRules": []map[string]any{{"action": "allow", "ip": []string{"::1/128"}}}}
				}
				var server transport.Runtime
				if err := server.Apply(cfg); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { server.Close() })
				c, err := New(t.TempDir(), &transport.Dialer{Control: func(string, string, syscall.RawConn) error {
					directAttempts.Add(1)
					return errors.New("protected traffic attempted direct connection")
				}})
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(c.Close)
				c.config.TrafficMode = TrafficSelective
				app := testApp("a")
				c.apps[app.ID] = model.Application{ApplicationInfo: app, Decision: decision}
				source := netip.MustParseAddrPort("[fd04:6c69:6e65:ffff::1]:12345")
				c.SetOwnerLookup(func(_ context.Context, network string, src, dst netip.AddrPort) (model.ApplicationInfo, error) {
					if network != "tcp" || src != source || dst != destination {
						t.Error("owner lookup lost the original IPv6 tuple")
					}
					return app, nil
				})
				p := model.Profile{AccountID: "a", DeviceID: "d", Status: "active", Rules: rules, UUID: device.Secret,
					Server: "127.0.0.1", Port: port, SNI: options.SNI, PublicKey: options.PublicKey, ShortID: options.ShortID, Path: options.Path}
				if decision == "trusted" {
					p.AppUUID = device.AppSecret
				}
				if err := c.apply(p); err != nil {
					t.Fatal(err)
				}
				roundTrip := func(wantFailure bool) {
					left, right := net.Pipe()
					defer right.Close()
					ctx, cancel := context.WithCancel(context.Background())
					defer cancel()
					finished := make(chan error, 1)
					c.NewConnectionEx(ctx, left, M.SocksaddrFrom(source.Addr(), source.Port()), M.SocksaddrFrom(destination.Addr(), destination.Port()), func(err error) { finished <- err })
					right.SetDeadline(time.Now().Add(8 * time.Second))
					payload := []byte("selective-ipv6")
					if _, err := right.Write(payload); err != nil {
						t.Fatal(err)
					}
					response := make([]byte, len(payload))
					n, readErr := io.ReadFull(right, response)
					if wantFailure {
						if readErr == nil || n != 0 || exitAttempts.Load() == 0 {
							t.Fatalf("did not reproduce exit failure: read=%v bytes=%d exit attempts=%d", readErr, n, exitAttempts.Load())
						}
					} else if readErr != nil || string(response) != string(payload) {
						t.Fatal("selective IPv6 round trip failed", readErr)
					}
					right.Close()
					// Explicitly end this test flow: a clean upload EOF alone
					// now preserves a potentially outstanding server response.
					cancel()
					select {
					case <-finished:
					case <-time.After(3 * time.Second):
						t.Fatal("flow did not stop")
					}
					if directAttempts.Load() != 0 {
						t.Fatal("protected flow attempted direct egress")
					}
					c.mu.RLock()
					issues := c.vpnIssuesLocked()
					mode := c.trafficModeLocked()
					c.mu.RUnlock()
					if mode != TrafficSelective {
						t.Fatal("test escaped to full mode")
					}
					if wantFailure {
						if len(issues) != 1 || issues[0].Target != destination.Addr().String() || issues[0].Source.ID != app.ID {
							t.Fatal("server exit failure did not produce the reported IPv6 issue", issues)
						}
					} else if len(issues) != 0 {
						t.Fatal("successful flow reported an outage", issues)
					}
				}
				roundTrip(egress != "round-trip")
				if egress == "exit-recovery" {
					// Restore only server egress. Keep the same client, credentials,
					// policy and Xray instance to exercise an ordinary app retry.
					temporarilyUnreachable.Store(false)
					roundTrip(false)
				}
			})
		}
	}
}
