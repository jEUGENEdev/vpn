package client

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/jEUGENEdev/vpn/internal/transport"
)

type networkStub struct {
	check func(bool) error
	apply func(bool) error
}

func (n networkStub) Check(v bool) error {
	if n.check != nil {
		return n.check(v)
	}
	return nil
}
func (n networkStub) Apply(v bool) error { return n.apply(v) }

func TestPowerWaitsForNativeNetworkAndRetriesCleanup(t *testing.T) {
	c, err := New(t.TempDir(), &transport.Dialer{})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetTunnel(true)
	c.SetGuard(true)
	calls := 0
	c.SetNetworkController(networkStub{apply: func(enabled bool) error {
		calls++
		state := c.State().(map[string]any)
		if state["status"] != "switching" {
			t.Fatal("reported final state before OS cleanup", state)
		}
		if calls == 1 {
			return errors.New("DNS restore failed")
		}
		c.SetTunnel(enabled)
		c.SetGuard(enabled)
		return nil
	}})
	if c.SetVPNEnabled(false) == nil {
		t.Fatal("cleanup failure hidden")
	}
	state := c.State().(map[string]any)
	if state["status"] != "network_error" || state["power_error"] == "" {
		t.Fatal(state)
	}
	if err = c.SetVPNEnabled(false); err != nil {
		t.Fatal(err)
	}
	state = c.State().(map[string]any)
	if calls != 2 || state["status"] != "disabled" || state["tunnel"] != false || state["guard"] != false {
		t.Fatal(state, calls)
	}
	if err = c.SetVPNEnabled(true); err != nil {
		t.Fatal(err)
	}
	state = c.State().(map[string]any)
	if calls != 3 || state["tunnel"] != true || state["guard"] != true {
		t.Fatal(state, calls)
	}
}

func TestSystemLockdownVetoDoesNotPersistOff(t *testing.T) {
	dir := t.TempDir()
	c, err := New(dir, &transport.Dialer{})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetNetworkController(networkStub{check: func(bool) error { return errors.New("Android lockdown") }, apply: func(bool) error { t.Fatal("OS changed after veto"); return nil }})
	if c.SetVPNEnabled(false) == nil || !c.VPNEnabled() {
		t.Fatal("lockdown was presented as off")
	}
	if _, err = os.Stat(filepath.Join(dir, "profile.json")); !os.IsNotExist(err) {
		t.Fatal("veto persisted an off request")
	}
}

func TestNativeRestartPersistsIntentWithoutFalseCompletion(t *testing.T) {
	dir := t.TempDir()
	c, err := New(dir, &transport.Dialer{})
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	c.SetNetworkController(networkStub{apply: func(bool) error { calls++; return ErrNetworkRestart }})
	if err = c.SetVPNEnabled(false); err != nil {
		t.Fatal(err)
	}
	state := c.State().(map[string]any)
	if state["status"] != "switching" || state["power_transition"] != true {
		t.Fatal(state)
	}
	if err = c.SetVPNEnabled(false); err != nil || calls != 1 {
		t.Fatal("duplicate restart", calls, err)
	}
	c.Close()
	c, err = New(dir, &transport.Dialer{})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if c.VPNEnabled() {
		t.Fatal("restart lost off intent")
	}
	if c.State().(map[string]any)["power_transition"] != false {
		t.Fatal("restart did not finish transition")
	}
}

func TestOffDoesNotPollVPNServer(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		http.Error(w, "revoked", http.StatusUnauthorized)
	}))
	defer server.Close()
	c, err := New(t.TempDir(), &transport.Dialer{})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.config.API, c.config.Profile.Token, c.http = server.URL, "device-token", server.Client()
	if err = c.SetVPNEnabled(false); err != nil {
		t.Fatal(err)
	}
	if err = c.sync(context.Background(), true); err != nil {
		t.Fatal(err)
	}
	if requests.Load() != 0 {
		t.Fatal("background sync continued while off")
	}
	// Explicit account actions (key rotation / device removal) still refresh
	// their results and invalidate a revoked local session while VPN is off.
	if err = c.Sync(context.Background()); err == nil || requests.Load() != 1 || c.config.Profile.Token != "" {
		t.Fatal("explicit account refresh was skipped", err)
	}
}
