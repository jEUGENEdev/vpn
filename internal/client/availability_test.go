package client

import (
	"context"
	"io"
	"net"
	"testing"
	"testing/synctest"
	"time"

	"github.com/jEUGENEdev/vpn/internal/model"
	"github.com/jEUGENEdev/vpn/internal/policy"
	"github.com/jEUGENEdev/vpn/internal/secure"
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
	key := fallbackKey{Target: "127.0.0.1", Network: "tcp", Port: uint16(ln.Addr().(*net.TCPAddr).Port)}
	c.fallbacks[key] = time.Now().Add(-time.Second)
	if c.routeFlowLocked(key.Target, key.AppID, key.Network, key.Port) != policy.VPN {
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
	if c.routeFlowLocked("example.com", "", "", 0) != policy.Direct {
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
	if c.routeFlowLocked("example.com", "", "", 0) != policy.Direct {
		t.Fatal("write-only failure kept selecting VPN")
	}
}

func TestFailureFallbackIsScopedToDestinationAndApplication(t *testing.T) {
	c := testTrafficClient(t)
	c.ready = true
	c.config.Profile.Rules = []string{"example.com", "media.example.org"}
	failed := activeFlow{Target: "example.com", AppID: "browser", Network: "tcp", Port: 443, Route: policy.VPN}
	left, right := net.Pipe()
	defer right.Close()
	c.active[left] = failed
	flow := &tracked{Conn: left, c: c}
	flow.reportResponseTimeout()
	if c.routeFlowLocked(failed.Target, failed.AppID, failed.Network, failed.Port) != policy.Direct {
		t.Fatal("failed destination has no fallback")
	}
	for _, other := range []activeFlow{
		{Target: "media.example.org", AppID: "browser", Network: "tcp", Port: 443},
		{Target: "example.com", AppID: "messenger", Network: "tcp", Port: 443},
		{Target: "example.com", AppID: "browser", Network: "udp", Port: 443},
		{Target: "example.com", AppID: "browser", Network: "tcp", Port: 8443},
	} {
		if c.routeFlowLocked(other.Target, other.AppID, other.Network, other.Port) != policy.VPN {
			t.Fatalf("unrelated traffic escaped VPN: %+v", other)
		}
	}
	// A healthy stream from another destination cannot clear this cooldown.
	healthy, peer := net.Pipe()
	defer peer.Close()
	c.active[healthy] = activeFlow{Target: "media.example.org", Route: policy.VPN, Network: "tcp", Port: 443}
	trackedHealthy := &tracked{Conn: healthy, c: c}
	defer trackedHealthy.Close()
	go peer.Write([]byte("ok"))
	if _, err := io.ReadFull(trackedHealthy, make([]byte, 2)); err != nil {
		t.Fatal(err)
	}
	if !c.vpnFailed || c.routeFlowLocked(failed.Target, failed.AppID, failed.Network, failed.Port) != policy.Direct {
		t.Fatal("unrelated response cleared failed destination")
	}
}

func TestOneWayUDPMediaDoesNotStartDirectFallback(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c := testTrafficClient(t)
		c.ready = true
		c.config.Profile.Rules = []string{"media.example.org"}
		left, right := net.Pipe()
		defer right.Close()
		c.active[left] = activeFlow{Target: "media.example.org", Route: policy.VPN, Network: "udp", Port: 5004}
		flow := &tracked{Conn: left, c: c}
		defer flow.Close()
		go func() { io.Copy(io.Discard, right) }()
		if _, err := flow.Write([]byte("one-way-media")); err != nil {
			t.Fatal(err)
		}
		time.Sleep(firstResponseTimeout + time.Second)
		if c.vpnFailed || len(c.fallbacks) != 0 {
			t.Fatal("one-way media mistaken for VPN outage")
		}
		if _, err := flow.Write([]byte("still-uploading")); err != nil {
			t.Fatal("one-way media was terminated:", err)
		}
		// Expiring an idle UDP association is also not proof of VPN failure.
		flow.SetReadDeadline(time.Now().Add(time.Second))
		if _, err := flow.Read(make([]byte, 16)); err == nil {
			t.Fatal("expected idle deadline")
		}
		if c.vpnFailed {
			t.Fatal("UDP idle deadline started fallback")
		}
	})
}

func TestProfileExpansionPreservesUnchangedRoutes(t *testing.T) {
	c := testTrafficClient(t)
	p := model.Profile{Status: "active", UUID: secure.UUID(), Server: "127.0.0.1", Port: 443, PublicKey: secure.Token(), SNI: "example.com", ShortID: "12ab", Path: "/test", Rules: []string{"example.com"}, Revision: 1}
	if err := c.apply(p); err != nil {
		t.Fatal(err)
	}
	vpn, vpnPeer := net.Pipe()
	defer vpnPeer.Close()
	direct, directPeer := net.Pipe()
	defer directPeer.Close()
	newlyApproved, approvedPeer := net.Pipe()
	defer approvedPeer.Close()
	c.active[vpn] = activeFlow{Target: "example.com", Route: policy.VPN}
	c.active[direct] = activeFlow{Target: "direct.example.org", Route: policy.Direct}
	c.active[newlyApproved] = activeFlow{Target: "media.example.org", Route: policy.Direct}
	p.Revision++
	p.Rules = append(p.Rules, "media.example.org")
	if err := c.apply(p); err != nil {
		t.Fatal(err)
	}
	for _, live := range []net.Conn{vpn, direct} {
		if _, ok := c.active[live]; !ok {
			t.Fatal("unrelated connection interrupted by policy expansion")
		}
	}
	if _, err := approvedPeer.Read(make([]byte, 1)); err != io.EOF {
		t.Fatal("newly approved flow continued directly", err)
	}
	p.Revision++
	p.Rules = []string{"media.example.org"}
	if err := c.apply(p); err != nil {
		t.Fatal(err)
	}
	if _, err := vpnPeer.Read(make([]byte, 1)); err != io.EOF {
		t.Fatal("removed permission kept an old VPN stream", err)
	}
}
