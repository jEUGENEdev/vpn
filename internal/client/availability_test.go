package client

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/jEUGENEdev/vpn/internal/model"
	"github.com/jEUGENEdev/vpn/internal/policy"
)

func TestVPNDialFailureFallsBackAndCanRetryVPN(t *testing.T) {
	c := testTrafficClient(t)
	c.SetTunnel(true)
	c.config.Profile.Rules = []string{"127.0.0.1"}
	c.ready = true // Simulate a ready control plane with a missing transport.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	for i := 0; i < 3; i++ {
		conn, err := c.Dial(context.Background(), "tcp", "127.0.0.1", uint16(ln.Addr().(*net.TCPAddr).Port))
		if err != nil {
			t.Fatal("failed VPN prevented working direct dial", err)
		}
		conn.Close()
	}
	if !c.vpnFailed || c.State().(map[string]any)["direct_fallback"] != true {
		t.Fatal("fallback hidden")
	}
	if len(c.Events.List()) != 1 {
		t.Fatal("fallback notifications spammed", c.Events.List())
	}
	c.fallbacks[fallbackKey{"127.0.0.1", ""}] = time.Now().Add(-time.Second)
	if c.routeLocked("127.0.0.1", "") != policy.VPN {
		t.Fatal("VPN never retried")
	}
	if c.config.Disabled {
		t.Fatal("fallback overwrote user's enabled mode")
	}
}

func TestSilentVPNClosesWithoutReplayingAndNextConnectionIsDirect(t *testing.T) {
	c := testTrafficClient(t)
	c.ready = true
	c.config.Profile.Rules = []string{"example.com"}
	left, right := net.Pipe()
	defer right.Close()
	c.active[left] = activeFlow{Target: "example.com", Route: policy.VPN}
	flow := &tracked{Conn: left, c: c}
	flow.reportResponseTimeout()
	if _, err := right.Read(make([]byte, 1)); err != io.EOF {
		t.Fatal("stalled flow was not closed", err)
	}
	if c.routeLocked("example.com", "") != policy.Direct {
		t.Fatal("retry remained on broken VPN")
	}
	if len(c.active) != 0 {
		t.Fatal("stalled flow retained")
	}
}

func TestCancelledVPNDialDoesNotStartFallback(t *testing.T) {
	c := testTrafficClient(t)
	c.ready = true
	c.config.Profile.Rules = []string{"127.0.0.1"}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if conn, err := c.Dial(ctx, "tcp", "127.0.0.1", 80); err == nil {
		conn.Close()
		t.Fatal("cancelled dial succeeded")
	}
	if len(c.fallbacks) != 0 || c.vpnFailed {
		t.Fatal("cancellation changed network routing")
	}
}

func TestBrokenVPNRefreshKeepsExistingDirectConnection(t *testing.T) {
	c := testTrafficClient(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	conn, err := c.Dial(context.Background(), "tcp", "127.0.0.1", uint16(ln.Addr().(*net.TCPAddr).Port))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	for attempt := 0; attempt < 3; attempt++ {
		if err := c.apply(model.Profile{Status: "active", UUID: "invalid-credential", Server: "127.0.0.1", Port: 443}); err == nil {
			t.Fatal("broken VPN configuration accepted")
		}
		if _, err := conn.Write([]byte("still direct")); err != nil {
			t.Fatal("refresh interrupted working direct traffic", err)
		}
	}
}

func TestVPNWriteFailureEnablesFallbackWithoutARead(t *testing.T) {
	c := testTrafficClient(t)
	c.ready = true
	c.config.Profile.Rules = []string{"example.com"}
	left, right := net.Pipe()
	right.Close()
	c.active[left] = activeFlow{Target: "example.com", Route: policy.VPN}
	flow := &tracked{Conn: left, c: c}
	defer flow.Close()
	if _, err := flow.Write([]byte("not replayed")); err == nil {
		t.Fatal("expected write failure")
	}
	if c.routeLocked("example.com", "") != policy.Direct {
		t.Fatal("write-only failure kept selecting VPN")
	}
}
