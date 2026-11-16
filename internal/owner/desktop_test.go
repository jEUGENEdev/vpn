//go:build !android

package owner

import (
	"context"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestNativeTCPConnectionOwner(t *testing.T) {
	ln, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer ln.Close()
	done := make(chan net.Conn, 1)
	go func() { c, _ := ln.Accept(); done <- c }()
	conn, e := net.Dial("tcp", ln.Addr().String())
	if e != nil {
		t.Fatal(e)
	}
	defer conn.Close()
	remote := <-done
	if remote != nil {
		defer remote.Close()
	}
	src := conn.LocalAddr().(*net.TCPAddr).AddrPort()
	dst := conn.RemoteAddr().(*net.TCPAddr).AddrPort()
	p, e := rawLookup(context.Background(), "tcp", src, dst)
	if e != nil && os.Getenv("GITHUB_ACTIONS") != "true" && strings.Contains(e.Error(), "operation not permitted") {
		t.Skip("local sandbox blocks process/interface inspection; required on native CI runners")
	}
	if e != nil || p.PID != os.Getpid() || !filepath.IsAbs(p.Path) {
		t.Fatalf("native socket owner: %+v %v", p, e)
	}
}
func TestExecutableReplacementChangesTrustIdentity(t *testing.T) {
	path := filepath.Join(t.TempDir(), "browser")
	os.WriteFile(path, []byte("version one"), 0700)
	d := &Desktop{lookup: func(context.Context, string, netip.AddrPort, netip.AddrPort) (process, error) {
		return process{1, "browser", path}, nil
	}, cache: map[string]cachedIdentity{}}
	src, dst := netip.MustParseAddrPort("127.0.0.1:1234"), netip.MustParseAddrPort("127.0.0.1:443")
	a, e := d.Lookup(context.Background(), "tcp", src, dst)
	if e != nil {
		t.Fatal(e)
	}
	os.WriteFile(path, []byte("different executable"), 0700)
	now := time.Now().Add(time.Second)
	os.Chtimes(path, now, now)
	b, e := d.Lookup(context.Background(), "tcp", src, dst)
	if e != nil {
		t.Fatal(e)
	}
	if a.ID == b.ID {
		t.Fatal("changed binary inherited trust")
	}
}
