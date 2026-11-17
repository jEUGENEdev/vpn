package client

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"syscall"
	"testing"
	"testing/synctest"
	"time"

	"github.com/jEUGENEdev/vpn/internal/model"
	"github.com/jEUGENEdev/vpn/internal/policy"
)

// Exercise the same tracking wrapper used by the real TUN handler. An upload
// or slow server must remain usable beyond the old 20-second response limit.
func TestSilentProtectedTCPPreservesConnection(t *testing.T) {
	for _, route := range []policy.Route{policy.VPN, policy.AppVPN} {
		t.Run(string(route), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				c := testTrafficClient(t)
				c.ready = true
				left, right := net.Pipe()
				defer right.Close()
				c.active[left] = activeFlow{Target: "slow.example.com", Network: "tcp", Port: 443, Route: route}
				flow := &tracked{Conn: left, c: c}
				defer flow.Close()
				go io.Copy(io.Discard, right)
				for i := 0; i < 3; i++ {
					if _, err := flow.Write([]byte("upload")); err != nil {
						t.Fatal("upload interrupted", err)
					}
					time.Sleep(25 * time.Second)
				}
				if c.vpnFailed || len(c.Events.List()) != 0 {
					t.Fatal("slow response reported as VPN outage")
				}
				go right.Write([]byte("late response"))
				b := make([]byte, 32)
				if n, err := flow.Read(b); err != nil || string(b[:n]) != "late response" {
					t.Fatal("late response lost", err)
				}
			})
		})
	}
}

type syncRoundTripper func(*http.Request) (*http.Response, error)

func (f syncRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestTransientSyncPreservesLiveConnections(t *testing.T) {
	for _, failure := range []string{"timeout", "unavailable", "malformed"} {
		t.Run(failure, func(t *testing.T) {
			c := testTrafficClient(t)
			c.ready = true
			c.status = "ready"
			c.SetTunnel(true)
			c.config.API = "https://control.example.com"
			c.config.Profile = model.Profile{Status: "active", Token: "token", Rules: []string{"vpn.example.com"}}
			peers := map[policy.Route]net.Conn{}
			flows := map[policy.Route]net.Conn{}
			for _, route := range []policy.Route{policy.VPN, policy.AppVPN, policy.Direct} {
				left, right := net.Pipe()
				defer right.Close()
				c.active[left] = activeFlow{Target: "vpn.example.com", Network: "tcp", Port: 443, Route: route}
				peers[route], flows[route] = right, left
			}
			working := false
			c.http = &http.Client{Transport: syncRoundTripper(func(*http.Request) (*http.Response, error) {
				status, body := http.StatusOK, "{broken"
				if working {
					raw, _ := json.Marshal(syncResult{Profile: c.config.Profile})
					body = string(raw)
				} else {
					switch failure {
					case "timeout":
						return nil, os.ErrDeadlineExceeded
					case "unavailable":
						status = http.StatusServiceUnavailable
						body = `{"error":"temporarily unavailable"}`
					}
				}
				return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
			})}
			epoch := c.routeEpoch
			for i := 0; i < 3; i++ {
				if err := c.Sync(context.Background()); err == nil {
					t.Fatal("expected transient sync failure")
				}
				if !c.ready || c.routeEpoch != epoch || len(c.active) != 3 {
					t.Fatal("API failure changed live VPN state")
				}
			}
			if c.State().(map[string]any)["sync_pending"] != true {
				t.Fatal("sync failure hidden")
			}
			for route, conn := range flows {
				go peers[route].Write([]byte("alive"))
				conn.SetReadDeadline(time.Now().Add(time.Second))
				b := make([]byte, 5)
				if _, err := io.ReadFull(conn, b); err != nil || string(b) != "alive" {
					t.Fatalf("%s interrupted: %v", route, err)
				}
			}
			working = true
			if err := c.Sync(context.Background()); err != nil {
				t.Fatal(err)
			}
			if c.State().(map[string]any)["sync_pending"] != false || len(c.active) != 3 || c.routeEpoch != epoch {
				t.Fatal("successful sync restarted flows or kept stale warning")
			}
			if len(c.Events.List()) != 0 {
				t.Fatal("API outage produced false VPN disconnect/reconnect notifications", c.Events.List())
			}
		})
	}
}

func TestSyncRejectionStillRevokesLiveConnections(t *testing.T) {
	for _, status := range []int{401, 403} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			c := testTrafficClient(t)
			c.ready = true
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			app := testApp("a")
			c.apps[app.ID] = model.Application{ApplicationInfo: app, Decision: "trusted"}
			c.config.API = "https://control.example.com"
			c.config.Profile = model.Profile{Status: "active", Token: "secret", Rules: []string{"vpn.example.com"}, AppUUID: "secret-app", UUID: "secret-vpn"}
			c.http = &http.Client{Transport: syncRoundTripper(func(*http.Request) (*http.Response, error) {
				cancel() // A confirmed revocation wins over caller cancellation.
				return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(`{"error":"revoked"}`))}, nil
			})}
			var direct net.Conn
			for _, route := range []policy.Route{policy.VPN, policy.AppVPN, policy.Direct} {
				left, right := net.Pipe()
				defer right.Close()
				c.active[left] = activeFlow{Target: "vpn.example.com", Route: route}
				if route == policy.Direct {
					direct = left
				}
			}
			if err := c.Sync(ctx); err == nil {
				t.Fatal("revocation ignored")
			}
			if c.ready || c.config.Profile.Token != "" || len(c.active) != 1 {
				t.Fatal("revoked VPN flows retained")
			}
			if _, ok := c.active[direct]; !ok {
				t.Fatal("revocation closed unrelated direct flow")
			}
			if c.routeLocked("vpn.example.com", "") != policy.Block || c.routeLocked("app.example.com", app.ID) != policy.Block {
				t.Fatal("revoked protected traffic became direct")
			}
		})
	}
}

type lifecycleConn struct {
	net.Conn
	readErr, writeErr error
}

func (c lifecycleConn) Read([]byte) (int, error) { return 0, c.readErr }
func (c lifecycleConn) Write(p []byte) (int, error) {
	if c.writeErr != nil {
		return 0, c.writeErr
	}
	return len(p), nil
}

func TestProtectedLocalLifecycleDoesNotSignalOutage(t *testing.T) {
	for _, tc := range []struct {
		name     string
		err      error
		received bool
		writes   uint64
	}{
		{"unused EOF", io.EOF, false, 0},
		{"finished EOF", io.EOF, true, 1},
		{"read deadline", os.ErrDeadlineExceeded, false, 1},
		{"wrapped deadline", &net.OpError{Op: "read", Net: "tcp", Err: os.ErrDeadlineExceeded}, false, 1},
		{"cancelled", context.Canceled, false, 1},
		{"context deadline", context.DeadlineExceeded, false, 1},
		{"local close", net.ErrClosed, false, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := testTrafficClient(t)
			c.ready = true
			left, right := net.Pipe()
			defer right.Close()
			conn := lifecycleConn{Conn: left, readErr: tc.err}
			c.active[conn] = activeFlow{Target: "example.com", Network: "tcp", Port: 443, Route: policy.VPN}
			flow := &tracked{Conn: conn, c: c}
			defer flow.Close()
			flow.writes.Store(tc.writes)
			flow.received.Store(tc.received)
			if _, err := flow.Read(make([]byte, 1)); !errors.Is(err, tc.err) {
				t.Fatal("caller lost original error", err)
			}
			if c.vpnFailed || len(c.Events.List()) != 0 {
				t.Fatal("normal socket lifecycle marked VPN broken")
			}
		})
	}
}

func TestProtectedFailureIsScopedAndCountedOnce(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c := testTrafficClient(t)
		c.ready = true
		c.config.Profile.Rules = []string{"example.com"}
		left, right := net.Pipe()
		defer right.Close()
		conn := lifecycleConn{Conn: left, readErr: io.EOF, writeErr: syscall.ECONNRESET}
		key := flowKey{Target: "example.com", Network: "tcp", Port: 443}
		c.active[conn] = activeFlow{Target: key.Target, Network: key.Network, Port: key.Port, Route: policy.VPN}
		flow := &tracked{Conn: conn, c: c}
		defer flow.Close()
		flow.writes.Store(1)
		flow.Read(make([]byte, 1))
		first := c.vpnFailures[key]
		if !c.vpnFailed || first.IsZero() {
			t.Fatal("asynchronous VPN dial failure ignored")
		}
		time.Sleep(time.Second)
		flow.Write([]byte("retry"))
		if c.vpnFailures[key] != first {
			t.Fatal("read and write double-counted one broken connection")
		}
		c.recoverVPNLocked(flowKey{Target: "other.example.com"})
		time.Sleep(time.Minute)
		c.recoverVPNLocked(flowKey{Target: "other.example.com"})
		if !c.vpnFailed {
			t.Fatal("unrelated reply claimed recovery")
		}
		if c.routeFlowLocked(key) != policy.VPN {
			t.Fatal("error switched routing away from VPN")
		}
		c.recoverVPNLocked(key)
		if c.vpnFailed {
			t.Fatal("same endpoint recovery not recorded")
		}
	})
}

func TestProtectedDialNeverAttemptsDirectAfterFailure(t *testing.T) {
	for _, network := range []string{"tcp", "udp"} {
		t.Run(network, func(t *testing.T) {
			c := testTrafficClient(t)
			c.ready = true
			c.config.Profile.Rules = []string{"127.0.0.1"}
			attempts := 0
			c.Direct.Control = func(string, string, syscall.RawConn) error { attempts++; return errors.New("unexpected direct dial") }
			for i := 0; i < 3; i++ {
				if conn, err := c.Dial(context.Background(), network, "127.0.0.1", 443); err == nil {
					conn.Close()
					t.Fatal("missing VPN transport accepted connection")
				}
			}
			if attempts != 0 {
				t.Fatal("protected request attempted direct route", attempts)
			}
			if c.config.Disabled {
				t.Fatal("failure changed user mode")
			}
		})
	}
}
