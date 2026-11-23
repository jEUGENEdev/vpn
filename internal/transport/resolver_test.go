package transport

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// A real UDP truncation response must trigger a protected TCP DNS exchange.
// Everything listens on loopback; no public resolver or host DNS is changed.
func TestDirectResolverRetriesTruncatedDNSOverTCP(t *testing.T) {
	tcp, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { tcp.Close() })
	udp, err := net.ListenPacket("udp", tcp.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { udp.Close() })
	var udpQueries, tcpQueries, udpControls, tcpControls atomic.Int32
	handler := dns.HandlerFunc(func(w dns.ResponseWriter, q *dns.Msg) {
		r := new(dns.Msg)
		r.SetReply(q)
		r.RecursionAvailable = true
		if _, ok := w.RemoteAddr().(*net.UDPAddr); ok {
			udpQueries.Add(1)
			r.Truncated = true
		} else {
			tcpQueries.Add(1)
			r.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET}, A: net.IPv4(192, 0, 2, 7)}}
		}
		_ = w.WriteMsg(r)
	})
	for _, s := range []*dns.Server{{Listener: tcp, Handler: handler}, {PacketConn: udp, Handler: handler}} {
		started := make(chan struct{})
		s.NotifyStartedFunc = func() { close(started) }
		go func() { _ = s.ActivateAndServe() }()
		<-started
		t.Cleanup(func() { _ = s.Shutdown() })
	}
	resolver := directResolver(tcp.Addr().String(), func(network, address string, _ syscall.RawConn) error {
		if address != tcp.Addr().String() {
			return errors.New("resolver attempted an unexpected endpoint")
		}
		if strings.HasPrefix(network, "tcp") {
			tcpControls.Add(1)
		} else {
			udpControls.Add(1)
		}
		return nil
	})
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	ips, err := resolver.LookupNetIP(ctx, "ip4", "dns-fallback.example.")
	if err != nil {
		t.Fatalf("truncated UDP reply did not recover via TCP: %v (UDP=%d TCP=%d)", err, udpQueries.Load(), tcpQueries.Load())
	}
	if len(ips) != 1 || ips[0] != netip.MustParseAddr("192.0.2.7") {
		t.Fatalf("unexpected DNS answer: %v", ips)
	}
	if udpQueries.Load() == 0 || tcpQueries.Load() == 0 || udpControls.Load() == 0 || tcpControls.Load() == 0 {
		t.Fatal("DNS retry skipped UDP, TCP or socket protection")
	}
}

func TestDirectResolverNeverIgnoresSocketProtectionFailure(t *testing.T) {
	for _, network := range []string{"udp", "tcp"} {
		t.Run(network, func(t *testing.T) {
			denied := errors.New("socket protection denied")
			var controls atomic.Int32
			resolver := directResolver("127.0.0.1:53", func(string, string, syscall.RawConn) error {
				controls.Add(1)
				return denied
			})
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			conn, err := resolver.Dial(ctx, network, "ignored.example:53")
			if conn != nil {
				conn.Close()
				t.Fatal("DNS escaped socket protection")
			}
			if !errors.Is(err, denied) || controls.Load() != 1 {
				t.Fatalf("socket protection failure lost: %v", err)
			}
		})
	}
}
