package client

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/jEUGENEdev/vpn/internal/model"
	"github.com/jEUGENEdev/vpn/internal/secure"
	"github.com/jEUGENEdev/vpn/internal/store"
	"github.com/jEUGENEdev/vpn/internal/transport"
	M "github.com/sagernet/sing/common/metadata"
)

type uploadEOFConn struct {
	net.Conn
	eof  chan struct{}
	once sync.Once
}

func (c *uploadEOFConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if errors.Is(err, io.EOF) {
		c.once.Do(func() { close(c.eof) })
	}
	return n, err
}

// An application can finish writing a framed upload while still waiting for
// its receipt. A real FIN must not discard that delayed receipt, including
// after an earlier server response has cleared VPN diagnostics.
func TestTCPUploadHalfCloseLifecycle(t *testing.T) {
	for _, scenario := range []struct{ route, finish string }{
		{"direct", "reply"}, {"vpn", "reply"}, {"vpn", "cancel"}, {"vpn", "policy"}, {"vpn", "idle"}, {"vpn", "reset"},
		{"xhttp", "reply"}, {"xhttp", "cancel"}, {"xhttp", "policy"}, {"xhttp", "reset"},
	} {
		t.Run(scenario.route+"/"+scenario.finish, func(t *testing.T) {
			route := scenario.route
			c := testTrafficClient(t)
			c.ready = true
			app := testApp("a")
			c.apps[app.ID] = model.Application{ApplicationInfo: app, Decision: "addresses"}
			if route == "vpn" {
				c.config.Profile.Rules = []string{"::1"}
				cfg := map[string]any{"log": map[string]any{"loglevel": "none"}, "outbounds": []map[string]any{{
					"protocol": "freedom", "settings": map[string]any{"finalRules": []map[string]any{{"action": "allow", "ip": []string{"::1/128"}}}},
				}}}
				if scenario.finish == "idle" {
					// Bound the fixture's existing Xray idle timeout, not production's.
					cfg["policy"] = map[string]any{"levels": map[string]any{"0": map[string]any{"connIdle": 1}}}
				}
				if err := c.vpn.Apply(cfg); err != nil {
					t.Fatal(err)
				}
			} else if route == "xhttp" {
				configureHalfCloseXHTTP(t, c)
			}
			var directAttempts atomic.Int32
			c.Direct.Control = func(string, string, syscall.RawConn) error {
				directAttempts.Add(1)
				if route != "direct" {
					return errors.New("protected upload attempted direct egress")
				}
				return nil
			}
			transport.InstallDialer(&transport.Dialer{Control: func(_, address string, _ syscall.RawConn) error {
				endpoint, err := netip.ParseAddrPort(address)
				if err != nil || !endpoint.Addr().IsLoopback() {
					return errors.New("half-close test prohibits external traffic")
				}
				return nil
			}})
			t.Cleanup(func() { transport.InstallDialer(&transport.Dialer{}) })
			origin, err := net.Listen("tcp6", "[::1]:0")
			if err != nil {
				t.Fatal(err)
			}
			defer origin.Close()
			application, inbound := halfCloseTCPPair(t)
			fin := &uploadEOFConn{Conn: inbound, eof: make(chan struct{})}
			payload := bytes.Repeat([]byte("upload-fixture"), 8192)
			receipt := bytes.Repeat([]byte("upload-accepted"), 1024)
			uploaded := make(chan error, 1)
			originDone := make(chan error, 1)
			replyAllowed := make(chan struct{})
			originCtx, stopOrigin := context.WithCancel(context.Background())
			defer stopOrigin()
			go func() {
				conn, err := origin.Accept()
				if err != nil {
					uploaded <- err
					originDone <- err
					return
				}
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(5 * time.Second))
				begin := make([]byte, 5)
				if _, err = io.ReadFull(conn, begin); err == nil && string(begin) != "begin" {
					err = errors.New("invalid upload preface")
				}
				if err == nil {
					_, err = conn.Write([]byte("ready"))
				}
				if err == nil {
					body := make([]byte, len(payload))
					_, err = io.ReadFull(conn, body)
					if err == nil && !bytes.Equal(body, payload) {
						err = errors.New("upload bytes changed")
					}
				}
				uploaded <- err
				if err == nil {
					select {
					case <-replyAllowed:
						_, err = conn.Write(receipt)
					case <-originCtx.Done():
					}
				}
				originDone <- err
			}()
			source := application.LocalAddr().(*net.TCPAddr).AddrPort()
			destination := origin.Addr().(*net.TCPAddr).AddrPort()
			c.SetOwnerLookup(func(_ context.Context, network string, src, dst netip.AddrPort) (model.ApplicationInfo, error) {
				if network != "tcp" || src != source || dst != destination {
					return model.ApplicationInfo{}, fmt.Errorf("upload lost its original IPv6 tuple")
				}
				return app, nil
			})
			finished := make(chan error, 1)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			c.NewConnectionEx(ctx, fin, M.SocksaddrFromNet(application.LocalAddr()), M.SocksaddrFromNet(origin.Addr()), func(err error) { finished <- err })
			// The first local REALITY connection also runs target probing;
			// keep this separate from the response-lifetime assertions below.
			application.SetDeadline(time.Now().Add(15 * time.Second))
			if _, err := application.Write([]byte("begin")); err != nil {
				t.Fatal(err)
			}
			ready := make([]byte, 5)
			if _, err := io.ReadFull(application, ready); err != nil || string(ready) != "ready" {
				t.Fatal("missing initial reply", err)
			}
			if _, err := application.Write(payload); err != nil {
				t.Fatal(err)
			}
			if err := <-uploaded; err != nil {
				t.Fatal("origin did not receive the complete upload", err)
			}
			if scenario.finish == "reset" {
				if err := application.SetLinger(0); err != nil {
					t.Fatal(err)
				}
				application.Close()
				select {
				case <-finished:
				case <-time.After(time.Second):
					t.Fatal("application reset retained its upstream connection")
				}
				stopOrigin()
				if err := <-originDone; err != nil {
					t.Fatal(err)
				}
				c.mu.RLock()
				defer c.mu.RUnlock()
				if len(c.active) != 0 || directAttempts.Load() != 0 {
					t.Fatal("reset retained a flow or attempted direct egress")
				}
				return
			}
			if err := application.CloseWrite(); err != nil {
				t.Fatal(err)
			}
			select {
			case <-fin.eof:
			case <-time.After(time.Second):
				t.Fatal("application FIN did not reach the TCP handler")
			}
			// The origin is processing the fully received file. Nothing has
			// finished the response direction yet.
			select {
			case <-finished:
				t.Fatal("upload FIN closed the response direction before the receipt")
			case <-time.After(100 * time.Millisecond):
			}
			switch scenario.finish {
			case "reply":
				close(replyAllowed)
			case "cancel":
				cancel()
			case "policy":
				if err := c.SetTrafficMode(TrafficAll); err != nil {
					t.Fatal(err)
				}
			}
			got, err := io.ReadAll(application)
			want := receipt
			if scenario.finish != "reply" {
				want = nil
			}
			if err != nil || !bytes.Equal(got, want) {
				t.Fatalf("wrong half-closed upload result: bytes=%d want=%d error=%v", len(got), len(want), err)
			}
			stopOrigin()
			if err := <-originDone; err != nil {
				t.Fatal(err)
			}
			select {
			case <-finished:
			case <-time.After(time.Second):
				t.Fatal("completed upload retained its tunnel flow")
			}
			if route != "direct" && directAttempts.Load() != 0 {
				t.Fatal("upload escaped the VPN")
			}
			c.mu.RLock()
			defer c.mu.RUnlock()
			if len(c.active) != 0 || len(c.vpnIssuesLocked()) != 0 {
				t.Fatal("completed upload left a flow or a VPN error")
			}
		})
	}
}

func configureHalfCloseXHTTP(t *testing.T, c *Client) {
	t.Helper()
	target := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("local REALITY target"))
	}))
	target.EnableHTTP2 = true
	target.TLS = &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13}
	target.StartTLS()
	t.Cleanup(target.Close)
	free, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := free.Addr().(*net.TCPAddr).Port
	free.Close()
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	options := transport.ServerOptions{Listen: "127.0.0.1", Port: port,
		PrivateKey: base64.RawURLEncoding.EncodeToString(key.Bytes()), PublicKey: base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes()),
		SNI: "example.com", Target: target.Listener.Addr().String(), ShortID: "12ab34cd", Path: "/half-close-test"}
	st := store.Empty()
	st.Accounts["a"] = store.Account{Account: model.Account{ID: "a", Status: "active", Rules: []string{"::1"}}}
	device := store.Device{Device: model.Device{ID: "d", AccountID: "a", Expires: time.Now().Add(time.Hour)}, Secret: secure.UUID()}
	st.Devices["d"] = device
	cfg := transport.ServerConfig(st, options, time.Now())
	// Loopback is permitted only in this test fixture.
	cfg["outbounds"].([]map[string]any)[1]["settings"] = map[string]any{"finalRules": []map[string]any{{"action": "allow", "ip": []string{"::1/128"}}}}
	var server transport.Runtime
	if err := server.Apply(cfg); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		c.Close()
		server.Close()
	})
	p := model.Profile{AccountID: "a", DeviceID: "d", Status: "active", Rules: []string{"::1"}, UUID: device.Secret,
		Server: "127.0.0.1", Port: port, SNI: options.SNI, PublicKey: options.PublicKey, ShortID: options.ShortID, Path: options.Path}
	if err := c.apply(p); err != nil {
		t.Fatal(err)
	}
}

func halfCloseTCPPair(t *testing.T) (*net.TCPConn, *net.TCPConn) {
	t.Helper()
	listener, err := net.ListenTCP("tcp6", &net.TCPAddr{IP: net.IPv6loopback})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	application, err := net.DialTCP("tcp6", nil, listener.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { application.Close() })
	inbound, err := listener.AcceptTCP()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { inbound.Close() })
	return application, inbound
}
