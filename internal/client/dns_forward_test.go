package client

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/jEUGENEdev/vpn/internal/model"
	"github.com/miekg/dns"
	M "github.com/sagernet/sing/common/metadata"
)

func fullDNSClient(t *testing.T, handler dns.HandlerFunc) *Client {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	started := make(chan struct{})
	srv := &dns.Server{Listener: listener, Handler: handler, NotifyStartedFunc: func() { close(started) }}
	go srv.ActivateAndServe()
	<-started
	t.Cleanup(func() { srv.Shutdown() })
	c := testTrafficClient(t)
	if err = c.SetTrafficMode(TrafficAll); err != nil {
		t.Fatal(err)
	}
	c.ready = true
	c.config.Profile.AppUUID = "configured"
	// A local test-only freedom redirect stands in for the VPN exit. The
	// production destination remains a public resolver, never this listener.
	if err = c.appVPN.Apply(map[string]any{"outbounds": []map[string]any{{"protocol": "freedom", "settings": map[string]any{"redirect": listener.Addr().String(), "finalRules": []map[string]any{{"action": "allow", "ip": []string{"127.0.0.1/32"}}}}}}}); err != nil {
		t.Fatal(err)
	}
	c.Direct.Control = func(string, string, syscall.RawConn) error {
		t.Error("DNS attempted direct socket")
		return errors.New("forbidden")
	}
	return c
}

func TestPublicSuffixHostDNS(t *testing.T) {
	for _, mode := range []string{TrafficSelective, TrafficAll} {
		t.Run(mode, func(t *testing.T) {
			var c *Client
			if mode == TrafficSelective {
				c = testTrafficClient(t)
			} else {
				c = fullDNSClient(t, func(w dns.ResponseWriter, q *dns.Msg) {
					r := new(dns.Msg)
					r.SetReply(q)
					h := dns.RR_Header{Name: q.Question[0].Name, Rrtype: q.Question[0].Qtype, Class: dns.ClassINET, Ttl: 60}
					if h.Rrtype == dns.TypeA {
						r.Answer = []dns.RR{&dns.A{Hdr: h, A: net.ParseIP("1.1.1.1")}}
					} else {
						r.Answer = []dns.RR{&dns.AAAA{Hdr: h, AAAA: net.ParseIP("2606:4700:4700::1111")}}
					}
					if err := w.WriteMsg(r); err != nil {
						t.Error(err)
					}
				})
			}
			for _, host := range []string{"sdmntprdenmarkeast.oaiusercontent.com", "sdmntprnortheu.oaiusercontent.com"} {
				for _, typ := range []uint16{dns.TypeA, dns.TypeAAAA} {
					q := new(dns.Msg)
					q.SetQuestion(dns.Fqdn(host), typ)
					wire, err := q.Pack()
					if err != nil {
						t.Fatal(err)
					}
					reply, err := c.answerDNS(context.Background(), wire, netip.MustParseAddr("172.29.255.2"), false)
					if err != nil {
						t.Fatal(err)
					}
					var r dns.Msg
					if err := r.Unpack(reply); err != nil {
						t.Fatal(err)
					}
					if r.Rcode != dns.RcodeSuccess || len(r.Answer) != 1 || r.Answer[0].Header().Rrtype != typ {
						t.Errorf("%s %s: rcode=%s answers=%v", host, dns.TypeToString[typ], dns.RcodeToString[r.Rcode], r.Answer)
						continue
					}
					var ip net.IP
					if typ == dns.TypeA {
						ip = r.Answer[0].(*dns.A).A
					} else {
						ip = r.Answer[0].(*dns.AAAA).AAAA
					}
					addr, _ := netip.AddrFromSlice(ip)
					if target, err := c.target(addr); err != nil || target != host {
						t.Errorf("%s routes to %q, want %q: %v", addr, target, host, err)
					}
				}
			}
		})
	}
}

func TestFullModeDNSPreservesRecordTypesThroughTunnel(t *testing.T) {
	var hits atomic.Int32
	c := fullDNSClient(t, func(w dns.ResponseWriter, q *dns.Msg) {
		hits.Add(1)
		r := new(dns.Msg)
		r.SetReply(q)
		var data string
		switch q.Question[0].Qtype {
		case dns.TypeA:
			data = "A 93.184.216.34"
		case dns.TypeAAAA:
			data = "AAAA 2606:4700::1111"
		case dns.TypeTXT:
			data = "TXT \"ordinary DNS response\""
		case dns.TypeSRV:
			data = "SRV 0 0 443 service.example.com."
		case dns.TypeHTTPS:
			data = "HTTPS 1 . alpn=\"h2,h3\" ech=AQID"
		}
		rr, err := dns.NewRR("example.com. 120 IN " + data)
		if err != nil {
			t.Error(err)
			return
		}
		r.Answer = []dns.RR{rr}
		w.WriteMsg(r)
	})
	for _, typ := range []uint16{dns.TypeA, dns.TypeAAAA, dns.TypeTXT, dns.TypeSRV, dns.TypeHTTPS} {
		q := new(dns.Msg)
		q.SetQuestion("example.com.", typ)
		payload, _ := q.Pack()
		for _, tcp := range []bool{false, true} {
			raw, err := c.answerDNS(context.Background(), payload, netip.MustParseAddr("172.29.255.2"), tcp)
			if err != nil {
				t.Fatal(err)
			}
			var r dns.Msg
			if err = r.Unpack(raw); err != nil {
				t.Fatal(err)
			}
			if len(r.Answer) != 1 || r.Answer[0].Header().Rrtype != typ || r.Answer[0].Header().Ttl != 0 {
				t.Fatal("DNS record lost or cached across modes", r.String())
			}
			if typ == dns.TypeHTTPS {
				found := false
				for _, value := range r.Answer[0].(*dns.HTTPS).Value {
					if ech, ok := value.(*dns.SVCBECHConfig); ok {
						found = bytes.Equal(ech.ECH, []byte{1, 2, 3})
					}
				}
				if !found {
					t.Fatal("ECH bytes were changed or stripped")
				}
			}
		}
	}
	if hits.Load() != 10 {
		t.Fatal("queries bypassed upstream", hits.Load())
	}
}

func TestFullModeDNSFailureAndStaleEpochNeverUseDirect(t *testing.T) {
	c := testTrafficClient(t)
	var direct atomic.Int32
	c.Direct.Control = func(string, string, syscall.RawConn) error { direct.Add(1); return errors.New("forbidden") }
	if err := c.SetTrafficMode(TrafficAll); err != nil {
		t.Fatal(err)
	}
	q := new(dns.Msg)
	q.SetQuestion("example.com.", dns.TypeHTTPS)
	payload, _ := q.Pack()
	for i := 0; i < 3; i++ {
		if _, err := c.answerDNS(context.Background(), payload, netip.MustParseAddr("8.8.8.8"), true); err == nil {
			t.Fatal("unavailable DNS tunnel returned success")
		}
	}
	epoch := c.routeEpoch
	if err := c.SetTrafficMode(TrafficSelective); err != nil {
		t.Fatal(err)
	}
	if _, err := c.dialAtEpoch(context.Background(), "tcp", "1.1.1.1", 53, model.ApplicationInfo{}, &epoch); err == nil {
		t.Fatal("stale DNS query escaped")
	}
	if direct.Load() != 0 {
		t.Fatal("DNS leaked directly")
	}
}

func TestFullModeDNSRejectsMismatchedResponse(t *testing.T) {
	c := fullDNSClient(t, func(w dns.ResponseWriter, q *dns.Msg) { r := new(dns.Msg); r.SetReply(q); r.Id++; w.WriteMsg(r) })
	q := new(dns.Msg)
	q.SetQuestion("example.com.", dns.TypeA)
	raw, _ := q.Pack()
	if _, err := c.answerDNS(context.Background(), raw, netip.MustParseAddr("1.1.1.1"), true); err == nil {
		t.Fatal("mismatched DNS response accepted")
	}
}

func TestFullModeIPv6KeepsDomainForVPNExitResolution(t *testing.T) {
	c := fullDNSClient(t, func(w dns.ResponseWriter, q *dns.Msg) {
		r := new(dns.Msg)
		r.SetReply(q)
		rr, _ := dns.NewRR("example.com. 60 IN AAAA 2a06:98c1:3101::ac40:9000")
		r.Answer = []dns.RR{rr}
		w.WriteMsg(r)
	})
	q := new(dns.Msg)
	q.SetQuestion("example.com.", dns.TypeAAAA)
	payload, _ := q.Pack()
	raw, err := c.answerDNS(context.Background(), payload, netip.MustParseAddr("172.29.255.2"), false)
	if err != nil {
		t.Fatal(err)
	}
	var response dns.Msg
	if err = response.Unpack(raw); err != nil || len(response.Answer) != 1 {
		t.Fatal("missing IPv6 answer", err)
	}
	ip, _ := netip.AddrFromSlice(response.Answer[0].(*dns.AAAA).AAAA)
	target, err := c.target(ip)
	if err != nil || target != "example.com" {
		t.Fatalf("IPv6 pinned the VPN exit to an address family instead of the domain: %q, %v", target, err)
	}
}

func TestFullModeDoesNotInventAddressesForNegativeDNSAnswers(t *testing.T) {
	for _, code := range []int{dns.RcodeSuccess, dns.RcodeNameError} {
		c := fullDNSClient(t, func(w dns.ResponseWriter, q *dns.Msg) {
			r := new(dns.Msg)
			r.SetRcode(q, code)
			w.WriteMsg(r)
		})
		q := new(dns.Msg)
		q.SetQuestion("example.com.", dns.TypeAAAA)
		payload, _ := q.Pack()
		raw, err := c.answerDNS(context.Background(), payload, netip.MustParseAddr("1.1.1.1"), true)
		if err != nil {
			t.Fatal(err)
		}
		var response dns.Msg
		if err = response.Unpack(raw); err != nil || response.Rcode != code || len(response.Answer) != 0 {
			t.Fatal("negative DNS answer turned into an address", response.String(), err)
		}
	}
}

func TestTunnelDNSHandlersForwardAndFailClosed(t *testing.T) {
	c := fullDNSClient(t, func(w dns.ResponseWriter, q *dns.Msg) {
		r := new(dns.Msg)
		r.SetReply(q)
		rr, _ := dns.NewRR("example.com. 60 IN TXT \"from-tunnel\"")
		r.Answer = []dns.RR{rr}
		w.WriteMsg(r)
	})
	q := new(dns.Msg)
	q.SetQuestion("example.com.", dns.TypeTXT)
	raw, _ := q.Pack()
	source := M.SocksaddrFrom(netip.MustParseAddr("172.29.255.1"), 40000)
	dest := M.SocksaddrFrom(netip.MustParseAddr("172.29.255.2"), 53)
	for _, available := range []bool{true, false} {
		c.mu.Lock()
		c.ready = available
		c.mu.Unlock()
		replies := make(udpReplies, 1)
		c.NewDNSPacket(raw, source, dest, replies)
		var udp []byte
		select {
		case reply := <-replies:
			udp = []byte(reply.payload)
		case <-time.After(3 * time.Second):
			t.Fatal("DNS UDP handler did not reply")
		}
		left, right := net.Pipe()
		finished := make(chan struct{})
		c.NewConnectionEx(context.Background(), left, source, dest, func(error) { close(finished) })
		right.SetDeadline(time.Now().Add(3 * time.Second))
		frame := make([]byte, len(raw)+2)
		binary.BigEndian.PutUint16(frame, uint16(len(raw)))
		copy(frame[2:], raw)
		if _, err := right.Write(frame); err != nil {
			t.Fatal(err)
		}
		var size [2]byte
		if _, err := io.ReadFull(right, size[:]); err != nil {
			t.Fatal(err)
		}
		tcp := make([]byte, binary.BigEndian.Uint16(size[:]))
		if _, err := io.ReadFull(right, tcp); err != nil {
			t.Fatal(err)
		}
		right.Close()
		<-finished
		for _, payload := range [][]byte{udp, tcp} {
			var response dns.Msg
			if err := response.Unpack(payload); err != nil {
				t.Fatal(err)
			}
			if available {
				if len(response.Answer) != 1 || response.Answer[0].(*dns.TXT).Txt[0] != "from-tunnel" {
					t.Fatal("DNS did not reach tunnel")
				}
			} else if response.Rcode != dns.RcodeServerFailure {
				t.Fatal("offline DNS did not fail closed")
			}
		}
	}
}

func TestFullModeDNSLargeUDPAnswerRequestsTCPRetry(t *testing.T) {
	c := fullDNSClient(t, func(w dns.ResponseWriter, q *dns.Msg) {
		r := new(dns.Msg)
		r.SetReply(q)
		for i := 0; i < 12; i++ {
			r.Answer = append(r.Answer, &dns.TXT{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 60}, Txt: []string{string(bytes.Repeat([]byte("a"), 100))}})
		}
		w.WriteMsg(r)
	})
	q := new(dns.Msg)
	q.SetQuestion("example.com.", dns.TypeTXT)
	raw, _ := q.Pack()
	udp, err := c.answerDNS(context.Background(), raw, netip.MustParseAddr("1.1.1.1"), false)
	if err != nil {
		t.Fatal(err)
	}
	var response dns.Msg
	if err = response.Unpack(udp); err != nil {
		t.Fatal(err)
	}
	if len(udp) > 512 || !response.Truncated {
		t.Fatal("large DNS UDP response was not truncated")
	}
	tcp, err := c.answerDNS(context.Background(), raw, netip.MustParseAddr("1.1.1.1"), true)
	if err != nil {
		t.Fatal(err)
	}
	if err = response.Unpack(tcp); err != nil {
		t.Fatal(err)
	}
	if response.Truncated || len(response.Answer) != 12 {
		t.Fatal("DNS TCP retry lost records")
	}
}
