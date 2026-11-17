package client

import (
	"github.com/miekg/dns"
	"net/netip"
	"testing"
)

func TestDNSPersistsAcrossRestart(t *testing.T) {
	dir := t.TempDir()
	f, e := OpenDNS(dir)
	if e != nil {
		t.Fatal(e)
	}
	q := new(dns.Msg)
	q.SetQuestion("Example.com.", dns.TypeA)
	raw, _ := q.Pack()
	res, e := f.Answer(raw)
	if e != nil {
		t.Fatal(e)
	}
	var msg dns.Msg
	msg.Unpack(res)
	if msg.Answer[0].Header().Ttl != 0 {
		t.Fatal("fake address can survive VPN disable in an application cache")
	}
	ip, _ := netip.AddrFromSlice(msg.Answer[0].(*dns.A).A)
	f.Close()
	f, e = OpenDNS(dir)
	if e != nil {
		t.Fatal(e)
	}
	defer f.Close()
	name, fake := f.Lookup(ip.Unmap())
	if !fake || name != "example.com" {
		t.Fatal(name, fake)
	}
	name, fake = f.Lookup(netip.MustParseAddr("198.19.255.250"))
	if !fake || name != "" {
		t.Fatal("unknown fake address must be blocked")
	}
}
