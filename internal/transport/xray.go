package transport

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/jEUGENEdev/vpn/internal/policy"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/core"
	_ "github.com/xtls/xray-core/main/distro/all"
	"github.com/xtls/xray-core/transport/internet"
	"google.golang.org/protobuf/proto"
)

type obj = map[string]any

type Runtime struct {
	mu       sync.RWMutex
	instance *core.Instance
	cancel   context.CancelFunc
	config   *core.Config
}

// ValidateConfig rejects invalid generated configuration before a server mutation
// commits. It creates no instance, listeners or live router changes.
func ValidateConfig(config obj) error {
	_, err := parseConfig(config)
	return err
}

func parseConfig(config obj) (*core.Config, error) {
	raw, err := json.Marshal(config)
	if err != nil {
		return nil, err
	}
	return core.LoadConfig("json", bytes.NewReader(raw))
}

func (r *Runtime) Apply(config obj) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	parsed, e := parseConfig(config)
	if e != nil {
		r.closeLocked()
		return e
	}
	if r.instance != nil {
		if proto.Equal(r.config, parsed) {
			return nil
		}
		if r.extendServer(parsed) {
			r.config = parsed
			return nil
		}
	}
	r.closeLocked()
	// Closing listeners alone leaves accepted XHTTP streams running. Cancel
	// the instance's inbound contexts as well when access/policy changes.
	ctx, cancel := context.WithCancel(context.Background())
	v, e := core.NewWithContext(ctx, parsed)
	if e != nil {
		cancel()
		return e
	}
	if e = v.Start(); e != nil {
		cancel()
		v.Close()
		return e
	}
	r.instance = v
	r.cancel = cancel
	r.config = parsed
	return nil
}
func (r *Runtime) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.closeLocked()
}

func (r *Runtime) closeLocked() error {
	r.config = nil
	if r.cancel != nil {
		r.cancel()
		r.cancel = nil
	}
	if r.instance != nil {
		e := r.instance.Close()
		r.instance = nil
		return e
	}
	return nil
}
func (r *Runtime) Dial(ctx context.Context, network, address string) (net.Conn, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.instance == nil {
		return nil, errors.New("VPN unavailable")
	}
	h, p, e := net.SplitHostPort(address)
	if e != nil {
		return nil, e
	}
	port, e := strconv.Atoi(p)
	if e != nil || port < 1 || port > 65535 {
		return nil, errors.New("invalid port")
	}
	d := xnet.TCPDestination(xnet.ParseAddress(h), xnet.Port(port))
	if network == "udp" {
		d.Network = xnet.Network_UDP
	}
	return core.Dial(ctx, r.instance, d)
}

// The stock Xray dialer logs and ignores controller errors. An alternative
// dialer is necessary so a failed Android protect()/interface bind is fatal.
type Dialer struct {
	Control    func(string, string, syscall.RawConn) error
	PublicOnly bool
	Deny       []netip.Prefix
	Resolver   *net.Resolver
}

func (d *Dialer) DestIpAddress() xnet.IP { return nil }
func (d *Dialer) Dial(ctx context.Context, _ xnet.Address, dest xnet.Destination, _ *internet.SocketConfig) (net.Conn, error) {
	return d.DialContext(ctx, dest.Network.SystemString(), dest.NetAddr())
}
func (d *Dialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	host, port, e := net.SplitHostPort(address)
	if e != nil {
		return nil, e
	}
	resolver := d.Resolver
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	var ips []netip.Addr
	if ip, e := netip.ParseAddr(host); e == nil {
		ips = []netip.Addr{ip}
	} else {
		ips, e = resolver.LookupNetIP(ctx, "ip", host)
		if e != nil {
			return nil, e
		}
	}
	var last error = errors.New("no permitted address")
	for _, ip := range ips {
		denied := false
		for _, prefix := range d.Deny {
			if prefix.Contains(ip.Unmap()) {
				denied = true
				break
			}
		}
		if denied {
			continue
		}
		if d.PublicOnly && !policy.Public(ip) {
			continue
		}
		nd := net.Dialer{Timeout: 10 * time.Second, Control: d.Control}
		conn, err := nd.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
		if err == nil {
			return conn, nil
		}
		last = err
	}
	return nil, last
}
func InstallDialer(d *Dialer) { internet.UseAlternativeSystemDialer(d) }
