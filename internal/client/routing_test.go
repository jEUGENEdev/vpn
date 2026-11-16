package client

import (
	"context"
	"github.com/jEUGENEdev/vpn/internal/model"
	"github.com/jEUGENEdev/vpn/internal/transport"
	"net"
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
	if !c.pending["127.0.0.1"] {
		t.Fatal("missing approval request")
	}
}
