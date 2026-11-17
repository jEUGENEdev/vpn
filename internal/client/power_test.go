package client

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/jEUGENEdev/vpn/internal/model"
	"github.com/jEUGENEdev/vpn/internal/policy"
	"github.com/jEUGENEdev/vpn/internal/secure"
	"github.com/jEUGENEdev/vpn/internal/transport"
)

func TestManualOffPersistsAndOfflineEnableBlocksProtectedTraffic(t *testing.T) {
	dir := t.TempDir()
	c, err := New(dir, &transport.Dialer{})
	if err != nil {
		t.Fatal(err)
	}
	c.config.Profile = model.Profile{AccountID: "a", Token: "offline", Rules: []string{"127.0.0.1"}}
	c.config.Pinned = []string{"pending.example"}
	c.apps["trusted"] = model.Application{Decision: "trusted"}
	if _, err = c.Action(context.Background(), "vpn", map[string]any{"enabled": false}); err == nil {
		t.Fatal("off lacked confirmation")
	}
	if _, err = c.Action(context.Background(), "vpn", map[string]any{"enabled": "false", "confirm": true}); err == nil {
		t.Fatal("malformed mode accepted")
	}
	if _, err = c.Action(context.Background(), "vpn", map[string]any{"enabled": false, "confirm": true}); err != nil {
		t.Fatal(err)
	}
	if c.routeLocked("pending.example", "") != policy.Direct || c.routeLocked("other.example", "trusted") != policy.Direct {
		t.Fatal("off retained VPN routes")
	}
	c.Close()
	c, err = New(dir, &transport.Dialer{})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if c.State().(map[string]any)["status"] != "disabled" {
		t.Fatal("off not persisted")
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	port := uint16(ln.Addr().(*net.TCPAddr).Port)
	flow, err := c.Dial(context.Background(), "tcp", "127.0.0.1", port)
	if err != nil {
		t.Fatal(err)
	}
	defer flow.Close()
	// Enabling while offline closes direct connections covered by saved rules.
	if _, err = c.Action(context.Background(), "vpn", map[string]any{"enabled": true}); err != nil {
		t.Fatal(err)
	}
	if c.disabled() {
		t.Fatal("failed sync reverted the user's protection")
	}
	if _, err = flow.Write([]byte("must not leak")); err == nil {
		t.Fatal("existing direct flow survived enable")
	}
	if c.routeLocked("127.0.0.1", "") != policy.Block || c.routeLocked("pending.example", "") != policy.Block {
		t.Fatal("saved rules lost")
	}
	if conn, err := c.Dial(context.Background(), "tcp", "127.0.0.1", port); err == nil {
		conn.Close()
		t.Fatal("offline enable leaked protected traffic")
	}
}

func TestVPNModeSaveFailureLeavesProtectionEnabled(t *testing.T) {
	c, err := New(t.TempDir(), &transport.Dialer{})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.config.Profile.Rules = []string{"example.com"}
	if err = os.Mkdir(filepath.Join(c.dir, "profile.json"), 0700); err != nil {
		t.Fatal(err)
	}
	if err = c.SetVPNEnabled(false); err == nil {
		t.Fatal("expected save error")
	}
	if c.disabled() || c.routeLocked("example.com", "") != policy.Block {
		t.Fatal("save failure changed routing")
	}
}

func TestInFlightDirectDialCannotSurvivePowerCycle(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	c, err := New(t.TempDir(), &transport.Dialer{Control: func(string, string, syscall.RawConn) error { close(entered); <-release; return nil }})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	result := make(chan error, 1)
	go func() {
		conn, err := c.Dial(context.Background(), "tcp", "127.0.0.1", uint16(ln.Addr().(*net.TCPAddr).Port))
		if conn != nil {
			conn.Close()
		}
		result <- err
	}()
	<-entered
	if err = c.SetVPNEnabled(false); err != nil {
		t.Fatal(err)
	}
	if err = c.SetVPNEnabled(true); err != nil {
		t.Fatal(err)
	}
	close(release)
	if err = <-result; err == nil {
		t.Fatal("in-flight connection escaped route generation")
	}
}

func TestBootstrapUpdatePreservesAccountAndDoesNotExposeSecrets(t *testing.T) {
	dir := t.TempDir()
	c, err := New(dir, &transport.Dialer{})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	pin, first, next := secure.Token(), secure.Token(), secure.Token()
	uri := "linevpn://8.8.8.8:8443?pin=" + pin + "&access="
	if err = c.SetBootstrap(uri + first); err != nil {
		t.Fatal(err)
	}
	c.config.Profile = model.Profile{AccountID: "alice", Login: "alice-name", Token: "device-token", Rules: []string{"example.com"}, Revision: 8}
	if err = c.SetBootstrap(uri + next); err != nil {
		t.Fatal(err)
	}
	if c.config.BootstrapKey != next || c.config.Profile.AccountID != "alice" || len(c.config.Profile.Rules) != 1 {
		t.Fatal("profile refresh lost identity or policy")
	}
	if err = c.SetBootstrap("linevpn://1.1.1.1:8443?pin=" + pin + "&access=" + next); err == nil {
		t.Fatal("bound account switched servers")
	}
	if err = c.SetBootstrap("linevpn://8.8.8.8:8443?pin=" + secure.Token() + "&access=" + next); err == nil {
		t.Fatal("bound account silently changed trust")
	}
	// Device deletion clears its session token, while the bound account and
	// trusted server must remain fixed for recovery.
	c.config.Profile.Token = ""
	if err = c.SetBootstrap("linevpn://1.1.1.1:8443?pin=" + pin + "&access=" + next); err == nil {
		t.Fatal("revoked account switched servers before reauthentication")
	}
	if err = c.SetBootstrap(uri + first); err != nil {
		t.Fatal("revoked account could not refresh the original server profile", err)
	}
	raw, _ := json.Marshal(c.State())
	if strings.Contains(string(raw), next) || strings.Contains(string(raw), "device-token") {
		t.Fatal("state leaked secrets")
	}
	if c.State().(map[string]any)["login"] != "alice-name" {
		t.Fatal("display name missing")
	}
}

func TestRegistrationSendsEnrollmentKeyWithoutSavingAccountKey(t *testing.T) {
	profileKey, accountKey := secure.Token(), "lnv_"+secure.Token()
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-LineVPN-Profile") != profileKey {
			t.Error("missing enrollment key")
		}
		if strings.Contains(r.URL.String(), profileKey) {
			t.Error("enrollment key exposed in URL")
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"access_key": accountKey, "status": "pending"})
	}))
	defer api.Close()
	c, err := New(t.TempDir(), &transport.Dialer{})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.config.API = api.URL
	c.config.BootstrapKey = profileKey
	c.http = api.Client()
	out, err := c.Auth(context.Background(), "register", map[string]any{"login": "alice"})
	if err != nil {
		t.Fatal(err)
	}
	if out.(map[string]any)["access_key"] != accountKey {
		t.Fatal("one-time key not delivered")
	}
	raw, _ := json.Marshal(c.config)
	if strings.Contains(string(raw), accountKey) {
		t.Fatal("account key persisted on client")
	}
}
