// Package mobile is the small JNI boundary owned by Android's VpnService.
package mobile

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/jEUGENEdev/vpn/internal/client"
	"github.com/jEUGENEdev/vpn/internal/secure"
	"github.com/jEUGENEdev/vpn/internal/transport"
	"github.com/jEUGENEdev/vpn/internal/ui"
	tun "github.com/sagernet/sing-tun"
	"net"
	"net/http"
	"path/filepath"
	"sync"
	"syscall"
	"time"
)

type Protector interface{ Protect(fd int64) bool }

var mu sync.Mutex
var current *session

type session struct {
	cancel context.CancelFunc
	c      *client.Client
	t      *client.Tunnel
	h      *http.Server
	url    string
}

func Start(fd int64, dir string, p Protector) (string, error) {
	mu.Lock()
	defer mu.Unlock()
	if current != nil {
		if fd > 0 {
			syscall.Close(int(fd))
		}
		return current.url, nil
	}
	if fd < 1 || p == nil {
		if fd > 0 {
			syscall.Close(int(fd))
		}
		return "", errors.New("VPN interface is required")
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
		syscall.Close(int(fd))
		return "", e
	}
	t, e := c.StartTunnel(ctx, tun.Options{Name: "linevpn", FileDescriptor: int(fd), AutoRoute: false, EXP_ExternalConfiguration: true})
	if e != nil {
		c.Close()
		cancel()
		return "", e
	}
	ln, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Close()
		c.Close()
		cancel()
		return "", e
	}
	token := secure.Token()
	h := &http.Server{Handler: c.Handler(token, ui.Handler("client")), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 20 * time.Second, WriteTimeout: 30 * time.Second}
	url := fmt.Sprintf("http://%s/#token=%s", ln.Addr(), token)
	current = &session{cancel, c, t, h, url}
	go h.Serve(ln)
	go c.Run(ctx)
	return url, nil
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
	current.t.Close()
	current.c.Close()
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
