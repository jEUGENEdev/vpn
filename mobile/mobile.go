// Package mobile is the small JNI boundary owned by Android's VpnService.
package mobile

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/jEUGENEdev/vpn/internal/client"
	"github.com/jEUGENEdev/vpn/internal/model"
	"github.com/jEUGENEdev/vpn/internal/secure"
	"github.com/jEUGENEdev/vpn/internal/transport"
	"github.com/jEUGENEdev/vpn/internal/ui"
	tun "github.com/sagernet/sing-tun"
	"net"
	"net/http"
	"net/netip"
	"path/filepath"
	"sync"
	"syscall"
	"time"
)

type Protector interface {
	Protect(fd int64) bool
	DeviceName() string
	ResolveApplication(network, source string, sourcePort int64, destination string, destinationPort int64) string
	OpenTunnel() (int64, error)
	CheckDisable() error
}

var mu sync.Mutex
var current *session

type session struct {
	cancel context.CancelFunc
	c      *client.Client
	t      *client.Tunnel
	h      *http.Server
	url    string
	ctx    context.Context
	p      Protector
}

func Start(dir string, p Protector) (string, error) {
	mu.Lock()
	defer mu.Unlock()
	if current != nil {
		return current.url, nil
	}
	if p == nil {
		return "", errors.New("VPN service is required")
	}
	ctx, cancel := context.WithCancel(context.Background())
	control := func(network, address string, raw syscall.RawConn) error {
		ok := false
		if e := raw.Control(func(fd uintptr) { ok = p.Protect(int64(fd)) }); e != nil {
			return e
		}
		if !ok {
			return errors.New("Android refused socket protection; connection blocked")
		}
		return nil
	}
	d := &transport.Dialer{Control: control}
	d.Resolver = &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
		return (&net.Dialer{Control: control, Timeout: 8 * time.Second}).DialContext(ctx, "udp", "1.1.1.1:53")
	}}
	transport.InstallDialer(d)
	c, e := client.New(filepath.Join(dir, "core"), d)
	if e != nil {
		cancel()
		return "", e
	}
	c.SetDeviceName(p.DeviceName())
	c.SetOwnerLookup(func(ctx context.Context, network string, source, dest netip.AddrPort) (model.ApplicationInfo, error) {
		raw := p.ResolveApplication(network, source.Addr().String(), int64(source.Port()), dest.Addr().String(), int64(dest.Port()))
		var app model.ApplicationInfo
		if len(raw) > 8192 || json.Unmarshal([]byte(raw), &app) != nil {
			return app, errors.New("application unavailable")
		}
		return app, nil
	})
	s := &session{cancel: cancel, c: c, ctx: ctx, p: p}
	// Keep the local UI alive with no VPN interface when off, including after
	// Android restarts an always-on service. Only explicit enable establishes it.
	if e = s.Apply(c.VPNEnabled()); e != nil {
		// Failed TUN creation must leave the UI available for off/retry. Apply
		// has closed any descriptor it received, so ordinary networking remains.
		c.SetNetworkError(e)
	}
	if !c.VPNEnabled() && p.CheckDisable() != nil {
		c.SetGuard(true)
	}
	c.SetNetworkController(s)
	ln, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		c.Close()
		if s.t != nil {
			s.t.Close()
		}
		cancel()
		return "", e
	}
	token := secure.Token()
	h := &http.Server{Handler: c.Handler(token, ui.Handler("client")), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 20 * time.Second, WriteTimeout: 30 * time.Second}
	url := fmt.Sprintf("http://%s/#token=%s", ln.Addr(), token)
	s.h, s.url = h, url
	current = s
	go h.Serve(ln)
	go c.Run(ctx)
	return url, nil
}

func (s *session) Check(enabled bool) error {
	if !enabled {
		return s.p.CheckDisable()
	}
	return nil
}

func (s *session) Apply(enabled bool) error {
	if s.t != nil {
		s.t.Close()
		s.t = nil
	}
	if !enabled {
		s.c.SetGuard(false)
		return nil
	}
	fd, err := s.p.OpenTunnel()
	if err != nil {
		return err
	}
	if fd < 1 {
		return errors.New("Android не разрешил VPN; откройте приложение и подтвердите подключение")
	}
	// Ownership transfers to StartTunnel (including its failure paths).
	s.t, err = s.c.StartTunnel(s.ctx, tun.Options{Name: "linevpn", FileDescriptor: int(fd), AutoRoute: false, EXP_ExternalConfiguration: true})
	return err
}
func URL() string {
	mu.Lock()
	defer mu.Unlock()
	if current == nil {
		return ""
	}
	return current.url
}
func Status() string {
	mu.Lock()
	defer mu.Unlock()
	if current == nil {
		return "stopped"
	}
	return "running"
}
func Stop() {
	mu.Lock()
	defer mu.Unlock()
	if current == nil {
		return
	}
	current.cancel()
	current.h.Close()
	current.c.Close()
	if current.t != nil {
		current.t.Close()
	}
	current = nil
}

func Snapshot() string {
	mu.Lock()
	defer mu.Unlock()
	if current == nil {
		return `{"status":"stopped"}`
	}
	raw, _ := json.Marshal(current.c.State())
	return string(raw)
}
func SetGuard(enabled bool) {
	mu.Lock()
	defer mu.Unlock()
	if current != nil {
		current.c.SetGuard(enabled)
	}
}
