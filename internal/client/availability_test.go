package client

import (
	"context"
	"io"
	"net"
	"os"
	"testing"
	"testing/synctest"
	"time"

	"github.com/jEUGENEdev/vpn/internal/model"
	"github.com/jEUGENEdev/vpn/internal/policy"
	"github.com/jEUGENEdev/vpn/internal/secure"
)

func TestVPNDialFailureKeepsProtectedRoute(t *testing.T) {
	c := testTrafficClient(t)
	app := testApp("a")
	c.apps[app.ID] = model.Application{ApplicationInfo: app, Decision: "addresses"}
	c.SetTunnel(true)
	c.config.Profile.Rules = []string{"127.0.0.1"}
	c.ready = true // Simulate a ready control plane with a missing transport.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	for i := 0; i < 3; i++ {
		conn, err := c.dialApplication(context.Background(), "tcp", "127.0.0.1", uint16(ln.Addr().(*net.TCPAddr).Port), app)
		if err == nil {
			conn.Close()
			t.Fatal("failed VPN escaped directly")
		}
	}
	if !c.vpnFailed || c.State().(map[string]any)["partial_outage"] != true {
		t.Fatal("failure hidden")
	}
	if len(c.Events.List()) != 1 {
		t.Fatal("failure notifications spammed", c.Events.List())
	}
	for key := range c.vpnFailures {
		c.vpnFailures[key] = time.Now().Add(-time.Second)
	}
	if c.routeLocked("127.0.0.1", app.ID) != policy.VPN {
		t.Fatal("VPN never retried")
	}
	if c.config.Disabled {
		t.Fatal("fallback overwrote user's enabled mode")
	}
}

func TestVPNFailureIsScopedToEndpointProtocolAndApplication(t *testing.T) {
	c := testTrafficClient(t)
	c.ready = true
	c.config.Profile.AppUUID = "app-key"
	app, other := testApp("a"), testApp("b")
	c.apps[app.ID] = model.Application{ApplicationInfo: app, Decision: "trusted"}
	c.apps[other.ID] = model.Application{ApplicationInfo: other, Decision: "trusted"}
	failed := flowKey{Target: "media.example.com", AppID: app.ID, Network: "udp", Port: 443}
	c.failVPNLocked(failed)
	if c.routeFlowLocked(failed) != policy.AppVPN {
		t.Fatal("failed endpoint lost VPN route")
	}
	for _, key := range []flowKey{
		{Target: failed.Target, AppID: app.ID, Network: "tcp", Port: 443},
		{Target: failed.Target, AppID: app.ID, Network: "udp", Port: 3478},
		{Target: failed.Target, AppID: other.ID, Network: "udp", Port: 443},
		{Target: "another.example.com", AppID: app.ID, Network: "udp", Port: 443},
	} {
		if c.routeFlowLocked(key) != policy.AppVPN {
			t.Fatalf("unrelated media route lost VPN: %+v", key)
		}
		c.recoverVPNLocked(key)
		if !c.vpnFailed || c.routeFlowLocked(failed) != policy.AppVPN {
			t.Fatal("another flow hid the failed endpoint")
		}
	}
	c.vpnFailures[failed] = time.Now().Add(-time.Second)
	if c.routeFlowLocked(failed) != policy.AppVPN {
		t.Fatal("failed endpoint did not retry VPN after cooldown")
	}
	c.recoverVPNLocked(failed)
	if c.vpnFailed {
		t.Fatal("endpoint recovery was not reported")
	}
}

type idleMediaConn struct{ net.Conn }

func (idleMediaConn) Read([]byte) (int, error) { return 0, os.ErrDeadlineExceeded }

func TestIdleMediaTimeoutDoesNotDisableVPN(t *testing.T) {
	c := testTrafficClient(t)
	c.ready = true
	c.config.Profile.Rules = []string{"example.com"}
	left, right := net.Pipe()
	defer right.Close()
	conn := idleMediaConn{left}
	c.active[conn] = activeFlow{Target: "example.com", Network: "udp", Port: 443, Route: policy.VPN}
	flow := &tracked{Conn: conn, c: c}
	defer flow.Close()
	flow.received.Store(true)
	flow.Read(make([]byte, 1))
	if c.vpnFailed || len(c.vpnFailures) != 0 {
		t.Fatal("normal idle UDP cleanup triggered direct fallback")
	}
}

func TestCancelledVPNDialDoesNotStartFallback(t *testing.T) {
	c := testTrafficClient(t)
	app := testApp("a")
	c.apps[app.ID] = model.Application{ApplicationInfo: app, Decision: "addresses"}
	c.ready = true
	c.config.Profile.Rules = []string{"127.0.0.1"}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if conn, err := c.dialApplication(ctx, "tcp", "127.0.0.1", 80, app); err == nil {
		conn.Close()
		t.Fatal("cancelled dial succeeded")
	}
	if len(c.vpnFailures) != 0 || c.vpnFailed {
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

func TestVPNWriteFailureRecordsOutageWithoutARead(t *testing.T) {
	c := testTrafficClient(t)
	app := testApp("a")
	c.apps[app.ID] = model.Application{ApplicationInfo: app, Decision: "addresses"}
	c.ready = true
	c.config.Profile.Rules = []string{"example.com"}
	left, right := net.Pipe()
	right.Close()
	c.active[left] = activeFlow{Target: "example.com", AppID: app.ID, Route: policy.VPN}
	flow := &tracked{Conn: left, c: c}
	defer flow.Close()
	if _, err := flow.Write([]byte("not replayed")); err == nil {
		t.Fatal("expected write failure")
	}
	if !c.vpnFailed || c.routeFlowLocked(flowKey{Target: "example.com", AppID: app.ID}) != policy.VPN {
		t.Fatal("write failure was hidden or bypassed VPN")
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
		if c.vpnFailed || len(c.vpnFailures) != 0 {
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
	app := testApp("a")
	c.apps[app.ID] = model.Application{ApplicationInfo: app, Decision: "addresses"}
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
	c.active[vpn] = activeFlow{Target: "example.com", AppID: app.ID, Route: policy.VPN}
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
