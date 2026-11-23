package client

import (
	"context"
	"errors"
	"net/netip"
	"time"

	"github.com/jEUGENEdev/vpn/internal/model"
	"github.com/jEUGENEdev/vpn/internal/policy"
	"github.com/miekg/dns"
)

// Full mode forwards all record types (including HTTPS/ECH, TXT and SRV)
// through the same protected transport as application traffic. The virtual
// resolver and private router addresses use a public resolver at the VPN exit.
// Never ask the OS resolver or retry on the direct dialer.
func (c *Client) answerDNS(ctx context.Context, payload []byte, destination netip.Addr, tcp bool) ([]byte, error) {
	c.mu.RLock()
	full := !c.config.Disabled && c.config.TrafficMode == TrafficAll
	epoch := c.routeEpoch
	closed := c.closed
	c.mu.RUnlock()
	if closed {
		return nil, errors.New("client stopped")
	}
	if !full {
		return c.DNS.Answer(payload)
	}
	var question dns.Msg
	if len(payload) > 4096 {
		return nil, errors.New("DNS query too large")
	}
	if err := question.Unpack(payload); err != nil {
		return nil, err
	}
	if question.Response || question.Opcode != dns.OpcodeQuery || len(question.Question) != 1 {
		return nil, errors.New("invalid DNS query")
	}
	if !policy.Public(destination) {
		destination = netip.MustParseAddr("1.1.1.1")
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	conn, err := c.dialAtEpoch(ctx, "tcp", destination.String(), 53, model.ApplicationInfo{}, &epoch)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	// TCP framing also works with Xray's stream connection, which need not
	// implement every deadline operation of a native TCPConn.
	wire := &dns.Conn{Conn: conn}
	if err = wire.WriteMsg(&question); err != nil {
		return nil, err
	}
	answer, err := wire.ReadMsg()
	if err != nil {
		return nil, err
	}
	if !answer.Response || answer.Id != question.Id || answer.Opcode != question.Opcode || len(answer.Question) != 1 || answer.Question[0] != question.Question[0] {
		return nil, errors.New("mismatched DNS response")
	}
	c.mu.RLock()
	current := !c.closed && c.routeEpoch == epoch
	c.mu.RUnlock()
	if !current {
		return nil, errors.New("policy changed during DNS query")
	}
	// Keep a domain behind A/AAAA destinations in full mode too. Sending a raw
	// AAAA address pins the exit to IPv6 even when that host is also available
	// over IPv4. Fake-IP lets the VPN exit resolve the domain and choose a usable
	// family, without any client-side/direct fallback. The upstream query still
	// travelled through VPN; preserve NXDOMAIN and NODATA instead of inventing
	// records for an address family which the authoritative answer lacks.
	typ := question.Question[0].Qtype
	if answer.Rcode == dns.RcodeSuccess && (typ == dns.TypeA || typ == dns.TypeAAAA) {
		for _, rr := range answer.Answer {
			if rr.Header().Rrtype == typ && rr.Header().Class == dns.ClassINET {
				return c.DNS.Answer(payload)
			}
		}
	}
	// Do not cache mode-specific answers across a switch back to Fake-IP.
	for _, section := range [][]dns.RR{answer.Answer, answer.Ns, answer.Extra} {
		for _, rr := range section {
			if rr.Header().Rrtype != dns.TypeOPT {
				rr.Header().Ttl = 0
			}
		}
	}
	if !tcp {
		limit := 512
		if opt := question.IsEdns0(); opt != nil {
			limit = max(512, min(int(opt.UDPSize()), 4096))
		}
		answer.Truncate(limit)
	}
	return answer.Pack()
}

func dnsFailure(payload []byte) []byte {
	var q dns.Msg
	if err := q.Unpack(payload); err != nil || q.Response {
		return nil
	}
	r := new(dns.Msg)
	r.SetRcode(&q, dns.RcodeServerFailure)
	answer, _ := r.Pack()
	return answer
}

func (c *Client) reserveDNS() bool {
	select {
	case c.dnsSlots <- struct{}{}:
		return true
	default:
		return false
	}
}
