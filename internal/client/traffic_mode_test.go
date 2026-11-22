package client

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/jEUGENEdev/vpn/internal/model"
	"github.com/jEUGENEdev/vpn/internal/policy"
	"github.com/jEUGENEdev/vpn/internal/transport"
)

func TestAddressPermissionRequiresApplicationConsent(t *testing.T) {
	c := testTrafficClient(t)
	c.ready = true
	c.config.Profile.Rules = []string{"example.com", "8.8.8.8", "2001:4860:4860::8888"}
	c.config.Profile.AppUUID = "configured"
	app := testApp("a")
	for _, decision := range []string{"pending", "denied", "addresses", "trusted"} {
		c.apps[app.ID] = model.Application{ApplicationInfo: app, Decision: decision}
		for _, target := range c.config.Profile.Rules {
			want := policy.Block
			if decision == "addresses" || decision == "trusted" {
				want = policy.VPN
			}
			if got := c.routeLocked(target, app.ID); got != want {
				t.Errorf("%s/%s: route %v, want %v", decision, target, got, want)
			}
			if got := c.routeLocked(target, ""); got != policy.Block {
				t.Errorf("unattributed flow inherited address permission: %v", got)
			}
		}
	}
}

func TestTrafficModePersistsAndRestoresSelectiveDecisions(t *testing.T) {
	c := testTrafficClient(t)
	app := testApp("a")
	c.apps[app.ID] = model.Application{ApplicationInfo: app, Decision: "denied"}
	if err := c.saveApplications(c.apps); err != nil {
		t.Fatal(err)
	}
	c.config.Profile.Rules = []string{"example.com"}
	if err := c.SetTrafficMode(TrafficAll); err != nil {
		t.Fatal(err)
	}
	dir := c.dir
	c.Close()
	reopened, err := New(dir, &transport.Dialer{})
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if reopened.State().(map[string]any)["traffic_mode"] != TrafficAll {
		t.Fatal("lost full mode")
	}
	for _, id := range []string{app.ID, ""} {
		if reopened.routeLocked("example.com", id) != policy.Block {
			t.Fatal("restart opened direct before VPN readiness")
		}
	}
	reopened.ready = true
	reopened.config.Profile.AppUUID = "configured"
	if reopened.routeLocked("elsewhere.org", app.ID) != policy.AppVPN || reopened.routeLocked("elsewhere.org", "") != policy.AppVPN {
		t.Fatal("explicit full mode did not cover all applications")
	}
	if err = reopened.SetTrafficMode(TrafficSelective); err != nil {
		t.Fatal(err)
	}
	if reopened.apps[app.ID].Decision != "denied" || reopened.routeLocked("example.com", app.ID) != policy.Block || reopened.routeLocked("elsewhere.org", app.ID) != policy.Direct {
		t.Fatal("full mode overwrote selective permissions")
	}
}

func TestTrafficModeSaveFailureKeepsExistingProtection(t *testing.T) {
	c := testTrafficClient(t)
	if err := c.SetTrafficMode(TrafficAll); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(c.dir, "profile.json")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(c.dir, "profile.json"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := c.SetTrafficMode(TrafficSelective); err == nil {
		t.Fatal("expected save failure")
	}
	if c.routeLocked("example.com", "") != policy.Block {
		t.Fatal("failed save opened direct traffic")
	}
	if _, err := c.Action(context.Background(), "traffic-mode", map[string]any{"mode": "unknown"}); err == nil {
		t.Fatal("invalid mode accepted")
	}
}

func TestModeChangeClosesFlowsAndRejectsInFlightDirectDial(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	c, err := New(t.TempDir(), &transport.Dialer{Control: func(string, string, syscall.RawConn) error { close(entered); <-release; return nil }})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	result := make(chan error, 1)
	go func() {
		conn, err := c.Dial(context.Background(), "tcp", "127.0.0.1", uint16(listener.Addr().(*net.TCPAddr).Port))
		if conn != nil {
			conn.Close()
		}
		result <- err
	}()
	<-entered
	left, right := net.Pipe()
	defer right.Close()
	c.mu.Lock()
	c.active[left] = activeFlow{Target: "example.com", Route: policy.Direct}
	c.mu.Unlock()
	if err = c.SetTrafficMode(TrafficAll); err != nil {
		t.Fatal(err)
	}
	right.SetReadDeadline(time.Now().Add(time.Second))
	if _, err = right.Read(make([]byte, 1)); err != io.EOF {
		t.Fatal("old direct flow survived full mode", err)
	}
	// Even switching back cannot revive a dial started under an older epoch.
	if err = c.SetTrafficMode(TrafficSelective); err != nil {
		t.Fatal(err)
	}
	close(release)
	if err = <-result; err == nil {
		t.Fatal("stale direct dial survived mode changes")
	}
}

func TestFullModeProvisionsAndRevokesBroadCredential(t *testing.T) {
	s, api, _ := policyServer(t)
	c := loginPolicyClient(t, s, api)
	if err := c.SetVPNEnabled(true); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Action(context.Background(), "traffic-mode", map[string]any{"mode": TrafficAll}); err != nil {
		t.Fatal(err)
	}
	if c.config.Profile.AppUUID == "" || c.routeLocked("example.com", "") != policy.AppVPN {
		t.Fatal("full mode did not provision the broad device credential")
	}
	if _, err := c.Action(context.Background(), "traffic-mode", map[string]any{"mode": TrafficSelective}); err != nil {
		t.Fatal(err)
	}
	if c.config.Profile.AppUUID != "" {
		t.Fatal("unused broad credential was not revoked")
	}
}

func TestDeniedApplicationClosesVPNFlowAndSyncs(t *testing.T) {
	s, api, _ := policyServer(t)
	c := loginPolicyClient(t, s, api)
	app := policyApp(c, "a")
	observe(t, c, "example.com", app, time.Now())
	c.config.Profile.Rules = []string{"example.com"}
	left, right := net.Pipe()
	defer right.Close()
	c.active[left] = activeFlow{Target: "example.com", AppID: app.ID, Route: policy.VPN}
	if _, err := c.Action(context.Background(), "applications", map[string]any{"id": app.ID, "decision": "denied"}); err != nil {
		t.Fatal(err)
	}
	right.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := right.Read(make([]byte, 1)); err != io.EOF {
		t.Fatal("denial kept a live VPN stream", err)
	}
	if !c.apps[app.ID].SyncConfirmed || c.apps[app.ID].Decision != "denied" {
		t.Fatal("denial not backed up")
	}
	fresh := loginPolicyClient(t, s, api)
	observe(t, fresh, "example.com", app, time.Now())
	if fresh.apps[app.ID].Decision != "denied" {
		t.Fatal("reinstall lost denial")
	}
}

func TestFullTrafficModeBlocksEveryDirectSocketWhenUnavailable(t *testing.T) {
	var direct atomic.Int32
	c, err := New(t.TempDir(), &transport.Dialer{Control: func(string, string, syscall.RawConn) error {
		direct.Add(1)
		return errors.New("direct socket attempted")
	}})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err = c.Action(context.Background(), "traffic-mode", map[string]any{"mode": "all"}); err != nil {
		t.Fatal(err)
	}
	for _, ready := range []bool{false, true} {
		c.ready = ready
		for _, credential := range []string{"", "configured"} {
			c.config.Profile.AppUUID = credential
			for _, network := range []string{"tcp", "udp"} {
				for _, target := range []string{"127.0.0.1", "::1", "media.example.org"} {
					for attempt := 0; attempt < 2; attempt++ {
						conn, err := c.Dial(context.Background(), network, target, 443)
						if conn != nil {
							conn.Close()
							t.Fatal("unavailable tunnel connected")
						}
						if !errors.Is(err, ErrVPNUnavailable) {
							t.Fatal(err)
						}
					}
				}
			}
		}
	}
	if direct.Load() != 0 {
		t.Fatalf("opened %d direct sockets", direct.Load())
	}
	if err = c.SetVPNEnabled(false); err != nil {
		t.Fatal(err)
	}
	_, _ = c.Dial(context.Background(), "tcp", "127.0.0.1", 443)
	if direct.Load() != 1 {
		t.Fatal("explicit off did not restore direct access")
	}
}

func TestUnapprovedApplicationCannotReachAllowedTunnelDestination(t *testing.T) {
	c := testTrafficClient(t)
	c.ready = true
	c.config.Profile.Rules = []string{"127.0.0.1"}
	if err := c.vpn.Apply(map[string]any{"outbounds": []map[string]any{{"protocol": "freedom", "settings": map[string]any{"finalRules": []map[string]any{{"action": "allow", "ip": []string{"127.0.0.1/32"}}}}}}}); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	app := testApp("b")
	conn, err := c.dialApplication(context.Background(), "tcp", "127.0.0.1", uint16(listener.Addr().(*net.TCPAddr).Port), app)
	if conn != nil {
		conn.Close()
		t.Fatal("unapproved app reached a globally approved destination through VPN")
	}
	if err == nil {
		t.Fatal("missing application permission was accepted")
	}
	if !errors.Is(err, ErrApplicationPermission) || c.vpnFailed || len(c.Events.List()) != 0 {
		t.Fatal("missing consent was misreported as a tunnel outage", err)
	}
}

func TestFullModeCarriesUnattributedTCPAndUDPOverBroadTunnel(t *testing.T) {
	for _, host := range []string{"127.0.0.1", "::1"} {
		for _, network := range []string{"tcp", "udp"} {
			t.Run(network+host, func(t *testing.T) {
				c := testTrafficClient(t)
				if err := c.SetTrafficMode(TrafficAll); err != nil {
					t.Fatal(err)
				}
				c.ready = true
				c.config.Profile.AppUUID = "configured"
				if err := c.appVPN.Apply(map[string]any{"outbounds": []map[string]any{{"protocol": "freedom", "settings": map[string]any{"finalRules": []map[string]any{{"action": "allow", "ip": []string{"127.0.0.1/32", "::1/128"}}}}}}}); err != nil {
					t.Fatal(err)
				}
				c.Direct.Control = func(string, string, syscall.RawConn) error {
					t.Error("full-mode application used direct socket")
					return errors.New("forbidden")
				}
				var port uint16
				if network == "tcp" {
					listener, err := net.Listen("tcp", net.JoinHostPort(host, "0"))
					if err != nil {
						t.Fatal(err)
					}
					defer listener.Close()
					port = uint16(listener.Addr().(*net.TCPAddr).Port)
					go func() {
						conn, err := listener.Accept()
						if err == nil {
							defer conn.Close()
							io.Copy(conn, conn)
						}
					}()
				} else {
					listener, err := net.ListenPacket("udp", net.JoinHostPort(host, "0"))
					if err != nil {
						t.Fatal(err)
					}
					defer listener.Close()
					port = uint16(listener.LocalAddr().(*net.UDPAddr).Port)
					go func() {
						b := make([]byte, 2048)
						n, peer, err := listener.ReadFrom(b)
						if err == nil {
							listener.WriteTo(b[:n], peer)
						}
					}()
				}
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				defer cancel()
				conn, err := c.Dial(ctx, network, host, port)
				if err != nil {
					t.Fatal(err)
				}
				defer conn.Close()
				stop := context.AfterFunc(ctx, func() { conn.Close() })
				defer stop()
				if _, err = conn.Write([]byte("unchanged")); err != nil {
					t.Fatal(err)
				}
				b := make([]byte, 9)
				if _, err = io.ReadFull(conn, b); err != nil || string(b) != "unchanged" {
					t.Fatal("full tunnel lost payload", err)
				}
				c.mu.RLock()
				defer c.mu.RUnlock()
				for _, flow := range c.active {
					if flow.Route != policy.AppVPN {
						t.Fatal("wrong credential", flow)
					}
				}
			})
		}
	}
}
