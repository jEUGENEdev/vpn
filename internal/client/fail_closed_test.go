package client

import (
	"context"
	"errors"
	"io"
	"net"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/jEUGENEdev/vpn/internal/model"
	"github.com/jEUGENEdev/vpn/internal/policy"
	"github.com/jEUGENEdev/vpn/internal/transport"
)

// Observe the real direct socket boundary, not just the selected route. Both
// the first failed VPN dial and all retries must leave it untouched.
func TestProtectedOutagesNeverOpenDirectSockets(t *testing.T) {
	for _, network := range []string{"tcp", "udp"} {
		for _, target := range []string{"127.0.0.1", "::1", "media.example.org"} {
			for _, protection := range []string{"address", "pending", "application"} {
				t.Run(network+"/"+target+"/"+protection, func(t *testing.T) {
					var direct atomic.Int32
					c, err := New(t.TempDir(), &transport.Dialer{Control: func(string, string, syscall.RawConn) error {
						direct.Add(1)
						return errors.New("direct socket attempted")
					}})
					if err != nil {
						t.Fatal(err)
					}
					defer c.Close()
					app := testApp("a")
					switch protection {
					case "address":
						c.config.Profile.Rules = []string{target}
					case "pending":
						c.config.Pinned = []string{target}
					case "application":
						c.apps[app.ID] = model.Application{ApplicationInfo: app, Decision: "trusted"}
					}
					for _, ready := range []bool{false, true} {
						c.ready = ready
						for _, credential := range []string{"", "configured"} {
							c.config.Profile.AppUUID = credential
							for attempt := 0; attempt < 3; attempt++ {
								conn, err := c.dialApplication(context.Background(), network, target, 443, app)
								if conn != nil {
									conn.Close()
									t.Fatal("unexpected connection")
								}
								if !errors.Is(err, ErrVPNUnavailable) {
									t.Fatalf("wrong outage: %v", err)
								}
							}
						}
					}
					// Failure expiry/eviction is only diagnostic; it cannot allow egress.
					for key := range c.vpnFailures {
						c.vpnFailures[key] = time.Now().Add(-time.Hour)
					}
					c.recoverVPNLocked(flowKey{})
					_, _ = c.dialApplication(context.Background(), network, target, 443, app)
					if direct.Load() != 0 {
						t.Fatalf("leaked %d direct socket attempts", direct.Load())
					}
					// Explicit off is the sole mode transition that bypasses protection.
					if err := c.SetVPNEnabled(false); err != nil {
						t.Fatal(err)
					}
					_, _ = c.dialApplication(context.Background(), network, "127.0.0.1", 443, app)
					if direct.Load() == 0 {
						t.Fatal("explicit off did not enable direct routing")
					}
				})
			}
		}
	}
}

func TestFailedProfileRefreshClosesNewlyProtectedDirectFlow(t *testing.T) {
	c := testTrafficClient(t)
	left, right := net.Pipe()
	defer right.Close()
	c.active[left] = activeFlow{Target: "media.example.org", Route: policy.Direct}
	if err := c.apply(model.Profile{Status: "active", UUID: "invalid", Rules: []string{"example.org"}}); err == nil {
		t.Fatal("invalid transport accepted")
	}
	right.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := right.Read(make([]byte, 1)); err != io.EOF {
		t.Fatal("newly protected direct flow survived failed refresh", err)
	}
	if c.routeLocked("media.example.org", "") != policy.Block {
		t.Fatal("failed refresh bypassed protection")
	}
}

func TestVPNReadFailureKeepsRetriesProtected(t *testing.T) {
	c := testTrafficClient(t)
	c.ready = true
	c.config.Profile.Rules = []string{"example.org"}
	left, right := net.Pipe()
	c.active[left] = activeFlow{Target: "example.org", Network: "tcp", Port: 443, Route: policy.VPN}
	flow := &tracked{Conn: left, c: c}
	defer flow.Close()
	// EOF is an upstream failure only after the client actually sent data.
	read := make(chan error, 1)
	go func() { _, err := io.ReadFull(right, make([]byte, 1)); read <- err }()
	if _, err := flow.Write([]byte{1}); err != nil {
		t.Fatal(err)
	}
	if err := <-read; err != nil {
		t.Fatal(err)
	}
	right.Close()
	_, _ = flow.Read(make([]byte, 1))
	if !c.vpnFailed || c.routeFlowLocked(flowKey{Target: "example.org", Network: "tcp", Port: 443}) != policy.VPN {
		t.Fatal("read failure bypassed VPN")
	}
}
