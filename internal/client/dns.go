package client

import (
	"encoding/binary"
	"errors"
	"github.com/jEUGENEdev/vpn/internal/policy"
	"github.com/jEUGENEdev/vpn/internal/secure"
	"github.com/miekg/dns"
	"go.etcd.io/bbolt"
	"net"
	"net/netip"
	"path/filepath"
	"time"
)

type FakeDNS struct{ db *bbolt.DB }

func OpenDNS(dir string) (*FakeDNS, error) {
	if e := secure.PrepareDirectory(dir); e != nil {
		return nil, e
	}
	db, e := bbolt.Open(filepath.Join(dir, "dns.db"), 0600, &bbolt.Options{Timeout: time.Second, OpenFile: secure.OpenPrivateFile})
	if e != nil {
		return nil, e
	}
	e = db.Update(func(tx *bbolt.Tx) error {
		_, e := tx.CreateBucketIfNotExists([]byte("names"))
		if e != nil {
			return e
		}
		_, e = tx.CreateBucketIfNotExists([]byte("ids"))
		return e
	})
	if e != nil {
		db.Close()
		return nil, e
	}
	return &FakeDNS{db}, nil
}
func (f *FakeDNS) Close() error { return f.db.Close() }
func (f *FakeDNS) ID(name string) (uint32, error) {
	var id uint32
	e := f.db.Update(func(tx *bbolt.Tx) error {
		names := tx.Bucket([]byte("names"))
		ids := tx.Bucket([]byte("ids"))
		if v := names.Get([]byte(name)); v != nil {
			id = binary.BigEndian.Uint32(v)
			return nil
		}
		n, e := names.NextSequence()
		if e != nil {
			return e
		}
		if n > 131069 {
			return errors.New("DNS mapping full")
		}
		id = uint32(n) + 1
		var raw [4]byte
		binary.BigEndian.PutUint32(raw[:], id)
		if e = names.Put([]byte(name), raw[:]); e != nil {
			return e
		}
		return ids.Put(raw[:], []byte(name))
	})
	return id, e
}
func fake4(id uint32) netip.Addr {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], 0xc6120000+id)
	return netip.AddrFrom4(b)
}
func fake6(id uint32) netip.Addr {
	b := [16]byte{0xfd, 0x04, 0x6c, 0x69, 0x6e, 0x65}
	binary.BigEndian.PutUint32(b[12:], id)
	return netip.AddrFrom16(b)
}
func IsFake(ip netip.Addr) bool {
	ip = ip.Unmap()
	return netip.MustParsePrefix("198.18.0.0/15").Contains(ip) || netip.MustParsePrefix("fd04:6c69:6e65::/96").Contains(ip)
}
func (f *FakeDNS) Lookup(ip netip.Addr) (string, bool) {
	ip = ip.Unmap()
	if !IsFake(ip) {
		return ip.String(), false
	}
	var id uint32
	if ip.Is4() {
		b := ip.As4()
		id = binary.BigEndian.Uint32(b[:]) - 0xc6120000
	} else {
		b := ip.As16()
		id = binary.BigEndian.Uint32(b[12:])
	}
	var out string
	f.db.View(func(tx *bbolt.Tx) error {
		var key [4]byte
		binary.BigEndian.PutUint32(key[:], id)
		out = string(tx.Bucket([]byte("ids")).Get(key[:]))
		return nil
	})
	return out, true
}
func (f *FakeDNS) Answer(payload []byte) ([]byte, error) {
	var q dns.Msg
	if e := q.Unpack(payload); e != nil {
		return nil, e
	}
	r := new(dns.Msg)
	r.SetReply(&q)
	r.RecursionAvailable = true
	if len(q.Question) != 1 {
		r.Rcode = dns.RcodeFormatError
		return r.Pack()
	}
	question := q.Question[0]
	name, e := policy.Normalize(question.Name)
	if e != nil {
		r.Rcode = dns.RcodeNameError
		return r.Pack()
	}
	if question.Qclass != dns.ClassINET {
		return r.Pack()
	}
	if question.Qtype == dns.TypeA || question.Qtype == dns.TypeAAAA {
		id, e := f.ID(name)
		if e != nil {
			r.Rcode = dns.RcodeServerFailure
			return r.Pack()
		}
		// Synthetic addresses must not outlive the VPN network in app caches.
		h := dns.RR_Header{Name: question.Name, Rrtype: question.Qtype, Class: dns.ClassINET, Ttl: 0}
		if question.Qtype == dns.TypeA {
			r.Answer = []dns.RR{&dns.A{Hdr: h, A: net.IP(fake4(id).AsSlice())}}
		} else {
			r.Answer = []dns.RR{&dns.AAAA{Hdr: h, AAAA: net.IP(fake6(id).AsSlice())}}
		}
	}
	return r.Pack()
}
