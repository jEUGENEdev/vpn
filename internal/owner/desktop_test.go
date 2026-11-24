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
	// Installers can preserve both the size and modification time when replacing a binary.
	stat, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	next := filepath.Join(filepath.Dir(path), "replacement")
	if err := os.WriteFile(next, []byte("version two"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(next, stat.ModTime(), stat.ModTime()); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(next, path); err != nil {
		t.Fatal(err)
	}
	b, e := d.Lookup(context.Background(), "tcp", src, dst)
	if e != nil {
		t.Fatal(e)
	}
	if a.ID == b.ID {
		t.Fatal("changed binary inherited trust")
	}
	if err := os.WriteFile(path, []byte("different executable"), 0700); err != nil {
		t.Fatal(err)
	}
	edited, err := d.Lookup(t.Context(), "tcp", src, dst)
	if err != nil || edited.ID == b.ID {
		t.Fatal("changed file inherited trust", err)
	}

}

func TestManualSelectionMatchesSocketAttribution(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	manual, err := IdentifySelection(t.Context(), exe)
	if err != nil {
		t.Fatal(err)
	}
	d := &Desktop{lookup: func(context.Context, string, netip.AddrPort, netip.AddrPort) (process, error) {
		return process{os.Getpid(), "network worker", exe}, nil
	}, cache: map[string]cachedIdentity{}}
	observed, err := d.Lookup(t.Context(), "tcp", netip.MustParseAddrPort("127.0.0.1:1234"), netip.MustParseAddrPort("127.0.0.1:443"))
	if err != nil || observed.ID != manual.ID || observed.Path != manual.Path {
		t.Fatal("manual identity does not match socket owner", err)
	}
	for _, invalid := range []string{"relative", t.TempDir(), filepath.Join(t.TempDir(), "missing")} {
		if _, err := IdentifySelection(t.Context(), invalid); err == nil {
			t.Fatal("invalid selection accepted", invalid)
		}
	}
}
