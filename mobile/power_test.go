package mobile

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/jEUGENEdev/vpn/internal/client"
	"github.com/jEUGENEdev/vpn/internal/transport"
)

type idleService struct {
	opens          int
	closes         int
	lockdown       bool
	all            bool
	applications   string
	catalogueError error
}

func (*idleService) Protect(int64) bool                                             { return true }
func (*idleService) DeviceName() string                                             { return "Test phone" }
func (*idleService) WaitTunnelReady(string) error                                   { return nil }
func (*idleService) ResolveApplication(string, string, int64, string, int64) string { return "{}" }
func (p *idleService) InstalledApplications() (string, error)                       { return "[]", p.catalogueError }
func (p *idleService) OpenTunnel(all bool, applications string) (int64, error) {
	p.opens++
	p.all, p.applications = all, applications
	return 0, errors.New("VPN permission revoked")
}

func TestAndroidCatalogueFailureKeepsRecoveryUI(t *testing.T) {
	p := &idleService{catalogueError: errors.New("package inventory unavailable")}
	url, err := Start(t.TempDir(), p)
	if err != nil {
		t.Fatal("catalogue failure lost the recovery UI", err)
	}
	defer Stop()
	if url == "" || p.opens != 1 || !strings.Contains(Snapshot(), "package inventory unavailable") {
		t.Fatal(Snapshot(), p.opens)
	}
	if err := current.c.SetVPNEnabled(false); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(Snapshot(), `"status":"disabled"`) {
		t.Fatal(Snapshot())
	}
}

func TestAndroidScopeReplacementFailureRetainsOldTunnel(t *testing.T) {
	c, err := client.New(t.TempDir(), &transport.Dialer{})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	p := &idleService{}
	tunnel := &testTunnel{c: c}
	c.SetTunnel(true)
	c.SetNetworkController(&session{c: c, p: p, t: tunnel, scope: "false:[]"})
	if err := c.SetTrafficMode(client.TrafficAll); err == nil {
		t.Fatal("native failure hidden")
	}
	if p.opens != 1 || !p.all || p.closes != 0 || tunnel.closes != 0 || c.State().(map[string]any)["traffic_mode"] != client.TrafficSelective {
		t.Fatal("failed establish released previous protection", p, tunnel)
	}
}
func (p *idleService) CloseTunnel() error { p.closes++; return nil }
func (p *idleService) CheckDisable() error {
	if p.lockdown {
		return errors.New("Android lockdown")
	}
	return nil
}

func TestAndroidOffStartupKeepsUIWithoutOpeningVPN(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "core"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "core/profile.json"), []byte(`{"vpn_disabled":true}`), 0600); err != nil {
		t.Fatal(err)
	}
	p := &idleService{}
	url, err := Start(dir, p)
	if err != nil {
		t.Fatal(err)
	}
	defer Stop()
	if p.opens != 0 || url == "" || !strings.Contains(Snapshot(), `"status":"disabled"`) {
		t.Fatal(Snapshot(), p.opens)
	}
	if err = current.c.SetVPNEnabled(true); err == nil {
		t.Fatal("native enable failure hidden")
	}
	if !strings.Contains(Snapshot(), `"status":"network_error"`) || p.opens != 1 {
		t.Fatal(Snapshot(), p.opens)
	}
	// The local UI still exists and explicit off can recover from a failed enable.
	if err = current.c.SetVPNEnabled(false); err != nil {
		t.Fatal(err)
	}
	if URL() != url || !strings.Contains(Snapshot(), `"status":"disabled"`) {
		t.Fatal(Snapshot())
	}
	Stop()
	p.lockdown = true
	if _, err = Start(dir, p); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(Snapshot(), `"status":"network_error"`) || p.opens != 2 {
		t.Fatal("lockdown falsely reported direct access", Snapshot())
	}
}

func TestAndroidStartupFailureLeavesControlUIAndNoTunnel(t *testing.T) {
	p := &idleService{}
	url, err := Start(t.TempDir(), p)
	if err != nil {
		t.Fatal("startup failure lost recovery UI", err)
	}
	defer Stop()
	if url == "" || p.opens != 1 || !strings.Contains(Snapshot(), `"status":"network_error"`) || !strings.Contains(Snapshot(), `"tunnel":false`) {
		t.Fatal(Snapshot(), url, p.opens)
	}
	if err := current.c.SetVPNEnabled(false); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(Snapshot(), `"status":"disabled"`) {
		t.Fatal(Snapshot())
	}
	Stop()
	Stop()
	if URL() != "" || p.opens != 1 {
		t.Fatal("shutdown recreated a tunnel")
	}
}

type testTunnel struct {
	c      *client.Client
	closes int
}

func (t *testTunnel) Close() { t.closes++; t.c.SetTunnel(false) }

func TestAndroidLockdownOffUsesDirectWithoutReleasingTunnel(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "profile.json"), []byte(`{"pending_protection":["127.0.0.1"]}`), 0600); err != nil {
		t.Fatal(err)
	}
	dials := 0
	c, err := client.New(dir, &transport.Dialer{Control: func(string, string, syscall.RawConn) error { dials++; return errors.New("observed direct socket") }})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	p := &idleService{lockdown: true}
	// Full-mode off/on can reuse the same device-wide local interface.
	if err := c.SetTrafficMode(client.TrafficAll); err != nil {
		t.Fatal(err)
	}
	tunnel := &testTunnel{c: c}
	c.SetTunnel(true)
	c.SetNetworkController(&session{c: c, p: p, t: tunnel, scope: "true:null"})
	if err = c.SetVPNEnabled(false); err != nil {
		t.Fatal(err)
	}
	state := c.State().(map[string]any)
	if state["status"] != "disabled" || state["tunnel"] != true || state["guard"] != true || tunnel.closes != 0 || p.opens != 0 || p.closes != 0 {
		t.Fatal(state, tunnel, p)
	}
	_, _ = c.Dial(context.Background(), "tcp", "127.0.0.1", 443)
	if dials != 1 {
		t.Fatal("off did not bypass VPN server")
	}
	if err = c.SetVPNEnabled(true); err != nil {
		t.Fatal(err)
	}
	if _, err = c.Dial(context.Background(), "tcp", "127.0.0.1", 443); !errors.Is(err, client.ErrVPNUnavailable) || dials != 1 {
		t.Fatal("offline re-enable leaked", err, dials)
	}
	p.lockdown = false
	if err = c.SetVPNEnabled(false); err != nil {
		t.Fatal(err)
	}
	if tunnel.closes != 1 || p.closes != 1 || c.State().(map[string]any)["tunnel"] != false {
		t.Fatal("ordinary off retained interface")
	}
}
