package client

import (
	"context"
	"github.com/jEUGENEdev/vpn/internal/model"
	"github.com/jEUGENEdev/vpn/internal/transport"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
)

func TestApprovedNeverDirectWhenOffline(t *testing.T) {
	c, e := New(t.TempDir(), &transport.Dialer{})
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	c.config.Profile = model.Profile{Rules: []string{"example.com", "127.0.0.1"}}
	c.ready = false
	ln, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer ln.Close()
	port := uint16(ln.Addr().(*net.TCPAddr).Port)
	if conn, e := c.Dial(context.Background(), "tcp", "127.0.0.1", port); e == nil {
		conn.Close()
		t.Fatal("approved IP leaked")
	}
	if _, e = c.Dial(context.Background(), "tcp", "api.example.com", 443); e == nil {
		t.Fatal("approved subdomain leaked")
	}
	if _, e = c.target(netip.MustParseAddr("198.18.4.4")); e == nil {
		t.Fatal("unknown fake address bypass")
	}
}
func TestUnapprovedDirect(t *testing.T) {
	c, e := New(t.TempDir(), &transport.Dialer{})
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	ln, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer ln.Close()
	conn, e := c.Dial(context.Background(), "tcp", "127.0.0.1", uint16(ln.Addr().(*net.TCPAddr).Port))
	if e != nil {
		t.Fatal(e)
	}
	conn.Close()
	if len(c.pending) != 0 || len(c.State().(map[string]any)["requests"].([]model.Request)) != 0 {
		t.Fatal("a working direct connection must not become a VPN suggestion")
	}
}

func TestApprovalProtectedBeforeServerAcknowledges(t *testing.T) {
	dir := t.TempDir()
	c, e := New(dir, &transport.Dialer{})
	if e != nil {
		t.Fatal(e)
	}
	_, e = c.Action(context.Background(), "rules", map[string]any{"target": "example.com", "action": "approve", "revision": 1})
	if e == nil {
		t.Fatal("server absent")
	}
	if conn, e := c.Dial(context.Background(), "tcp", "a.example.com", 443); e == nil {
		conn.Close()
		t.Fatal("pending approval fell back to direct")
	}
	c.Close()
	c, e = New(dir, &transport.Dialer{})
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	if conn, e := c.Dial(context.Background(), "tcp", "a.example.com", 443); e == nil {
		conn.Close()
		t.Fatal("pending protection lost after restart")
	}
}

func TestAuthenticationExpiryRetainsProtection(t *testing.T) {
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"error":"access expired"}`))
	}))
	defer api.Close()
	c, e := New(t.TempDir(), &transport.Dialer{})
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	c.config.API = api.URL
	c.config.Profile = model.Profile{AccountID: "a", Token: "expired", Rules: []string{"example.com"}}
	c.http = api.Client()
	c.ready = true
	if e = c.Sync(context.Background()); e == nil {
		t.Fatal("expected expired session")
	}
	if c.status != "auth_required" {
		t.Fatal(c.status)
	}
	if conn, e := c.Dial(context.Background(), "tcp", "example.com", 443); e == nil {
		conn.Close()
		t.Fatal("expired account fell back to direct")
	}
}

func TestApprovalClosesExistingDirectFlow(t *testing.T) {
	c, e := New(t.TempDir(), &transport.Dialer{})
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	ln, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer ln.Close()
	flow, e := c.Dial(context.Background(), "tcp", "127.0.0.1", uint16(ln.Addr().(*net.TCPAddr).Port))
	if e != nil {
		t.Fatal(e)
	}
	defer flow.Close()
	c.Action(context.Background(), "rules", map[string]any{"action": "approve", "target": "127.0.0.1", "revision": 0})
	if _, e = flow.Write([]byte("must not continue direct")); e == nil {
		t.Fatal("existing flow survived approval")
	}
}

func TestStoppedClientCannotOpenDirectConnections(t *testing.T) {
	c, err := New(t.TempDir(), &transport.Dialer{})
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	c.Close()
	c.Close()
	if conn, err := c.Dial(context.Background(), "tcp", "127.0.0.1", uint16(listener.Addr().(*net.TCPAddr).Port)); err == nil {
		conn.Close()
		t.Fatal("stopped client opened a direct connection")
	}
}
