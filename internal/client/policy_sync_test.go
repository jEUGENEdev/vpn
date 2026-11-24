package client

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jEUGENEdev/vpn/internal/model"
	"github.com/jEUGENEdev/vpn/internal/policy"
	"github.com/jEUGENEdev/vpn/internal/secure"
	"github.com/jEUGENEdev/vpn/internal/server"
	"github.com/jEUGENEdev/vpn/internal/store"
	"github.com/jEUGENEdev/vpn/internal/transport"
)

func policyServer(t *testing.T) (*server.Server, *httptest.Server, *atomic.Bool) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	if err = st.Update(func(v *store.State) error {
		v.Accounts["a"] = store.Account{Account: model.Account{ID: "a", Login: "alice", Status: "active", Revision: 1}, KeyHash: secure.Hash("lnv_" + strings.Repeat("a", 43))}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	s, err := server.New(st, server.Config{PublicIP: "127.0.0.1", Transport: transport.ServerOptions{Port: 443, SNI: "example.com", PublicKey: secure.Token(), ShortID: "12ab", Path: "/test"}}, "admin-password-very-long", nil)
	if err != nil {
		t.Fatal(err)
	}
	offline := &atomic.Bool{}
	handler := s.Handler()
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if offline.Load() {
			http.Error(w, "offline", 503)
			return
		}
		handler.ServeHTTP(w, r)
	}))
	t.Cleanup(api.Close)
	return s, api, offline
}

func loginPolicyClient(t *testing.T, s *server.Server, api *httptest.Server) *Client {
	t.Helper()
	c := testTrafficClient(t)
	c.config.Disabled = true // Exercise real HTTP/persistence without creating a VPN.
	c.config.API, c.http = api.URL, api.Client()
	if err := s.Store.View(func(st store.State) error { c.config.BootstrapKey = st.BootstrapKey; return nil }); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Auth(context.Background(), "login", map[string]any{"access_key": "lnv_" + strings.Repeat("a", 43)}); err != nil {
		t.Fatal(err)
	}
	return c
}

func policyApp(c *Client, letter string) model.ApplicationInfo {
	a := testApp(letter)
	a.Platform = c.identity.Platform
	return a
}

func TestPoliciesRestoreAfterCleanReinstallAndServerRestart(t *testing.T) {
	s, api, _ := policyServer(t)
	c := loginPolicyClient(t, s, api)
	ctx := context.Background()
	for _, target := range []string{"example.com", "8.8.8.8", "2001:4860:4860::8888"} {
		if _, err := c.Action(ctx, "rules", map[string]any{"target": target, "action": "approve", "revision": c.config.Profile.Revision}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := c.Action(ctx, "dismiss", map[string]any{"target": "direct.example.org"}); err != nil {
		t.Fatal(err)
	}
	for i, decision := range []string{"trusted", "addresses"} {
		a := policyApp(c, string(rune('a'+i)))
		observe(t, c, "local-history.example", a, time.Now())
		if _, err := c.Action(ctx, "applications", map[string]any{"id": a.ID, "decision": decision}); err != nil {
			t.Fatal(err)
		}
	}
	if c.pendingPolicyCountLocked() != 0 {
		t.Fatal("saved policy still pending")
	}
	oldDevice := c.config.Profile.DeviceID
	c.Close()
	// A real DB reopen proves choices are not kept only in the server process.
	dbPath := s.Store.DB.Path()
	if err := s.Store.Close(); err != nil {
		t.Fatal(err)
	}
	var err error
	s.Store, err = store.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Store.Close() })
	clean := loginPolicyClient(t, s, api)
	if clean.config.Profile.DeviceID == oldDevice {
		t.Fatal("clean install reused another device credential")
	}
	if len(clean.apps) != 0 {
		t.Fatal("server fabricated locally observed applications")
	}
	if err = clean.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	if len(clean.config.Profile.Rules) != 3 || !clean.dismissed["direct.example.org"] {
		t.Fatal("address or direct decisions lost")
	}
	for i, decision := range []string{"trusted", "addresses"} {
		a := policyApp(clean, string(rune('a'+i)))
		observe(t, clean, "after-reinstall.example", a, time.Now())
		if clean.apps[a.ID].Decision != decision || !clean.apps[a.ID].SyncConfirmed {
			t.Fatalf("%s decision not restored", decision)
		}
	}
	// Same display name/path is insufficient: changed executable/signature gets
	// a different OS identity and must not inherit the old trust.
	changed := policyApp(clean, "c")
	changed.Name, changed.Path = policyApp(clean, "a").Name, policyApp(clean, "a").Path
	observe(t, clean, "other.example", changed, time.Now())
	if clean.apps[changed.ID].Decision != "pending" {
		t.Fatal("changed executable inherited trust")
	}
	// Deleting an installation revokes access, not the account's saved policy.
	if _, err = clean.Action(ctx, "revoke", map[string]any{"id": oldDevice}); err != nil {
		t.Fatal(err)
	}
	newInstall := loginPolicyClient(t, s, api)
	if len(newInstall.config.Profile.ApplicationRules) != 2 {
		t.Fatal("device removal erased account decisions")
	}
}

func TestOfflineDecisionsRetryAfterRestartWhileVPNIsOff(t *testing.T) {
	s, api, offline := policyServer(t)
	c := loginPolicyClient(t, s, api)
	ctx := context.Background()
	app := policyApp(c, "a")
	observe(t, c, "example.com", app, time.Now())
	offline.Store(true)
	if _, err := c.Action(ctx, "rules", map[string]any{"target": "example.com", "action": "approve", "revision": c.config.Profile.Revision}); err == nil {
		t.Fatal("expected offline failure")
	}
	out, err := c.Action(ctx, "applications", map[string]any{"id": app.ID, "decision": "trusted"})
	if err != nil || out.(map[string]any)["pending"] != true {
		t.Fatal("offline decision not marked pending", out, err)
	}
	if c.State().(map[string]any)["policy_sync_pending"] != 2 {
		t.Fatal("pending changes hidden")
	}
	dir := c.dir
	c.Close()
	c, err = New(dir, &transport.Dialer{})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.http = api.Client()
	// Another device changed the revision while this installation was offline.
	if err = s.Store.Update(func(st *store.State) error {
		a := st.Accounts["a"]
		a.Rules = []string{"other.example"}
		a.Revision++
		st.Accounts["a"] = a
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	offline.Store(false)
	if err = c.sync(ctx, true); err != nil {
		t.Fatal(err)
	}
	if c.pendingPolicyCountLocked() != 0 || !policy.Approved(c.config.Profile.Rules, "example.com") || !policy.Approved(c.config.Profile.Rules, "other.example") {
		t.Fatal("queued or concurrent rules lost")
	}
	if c.VPNEnabled() || c.ready || c.routeLocked("example.com", app.ID) != policy.Direct {
		t.Fatal("backup turned VPN on")
	}
	reinstalled := loginPolicyClient(t, s, api)
	observe(t, reinstalled, "example.com", app, time.Now())
	if reinstalled.apps[app.ID].Decision != "trusted" || !policy.Approved(reinstalled.config.Profile.Rules, "example.com") {
		t.Fatal("retry did not persist to account")
	}
}

func TestLegacyAndSyncedAppsDoNotOverwriteNewerAccountDecision(t *testing.T) {
	s, api, _ := policyServer(t)
	first := loginPolicyClient(t, s, api)
	app := policyApp(first, "a")
	observe(t, first, "example.com", app, time.Now())
	ctx := context.Background()
	first.Action(ctx, "applications", map[string]any{"id": app.ID, "decision": "trusted"})
	second := loginPolicyClient(t, s, api)
	observe(t, second, "example.com", app, time.Now())
	if _, err := second.Action(ctx, "applications", map[string]any{"id": app.ID, "decision": "addresses"}); err != nil {
		t.Fatal(err)
	}
	if err := first.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	if first.apps[app.ID].Decision != "addresses" {
		t.Fatal("stale synchronized choice overwrote account")
	}
	legacy := loginPolicyClient(t, s, api)
	legacy.apps[app.ID] = model.Application{ApplicationInfo: app, Decision: "trusted"}
	// Exercise insert-only migration against an account that already has a rule.
	if err := legacy.syncSavedPolicy(ctx); err != nil {
		t.Fatal(err)
	}
	if legacy.apps[app.ID].Decision != "addresses" {
		t.Fatal("legacy migration overwrote newer decision")
	}
	newApp := policyApp(legacy, "b")
	legacy.apps[newApp.ID] = model.Application{ApplicationInfo: newApp, Decision: "trusted"}
	if err := legacy.syncSavedPolicy(ctx); err != nil {
		t.Fatal(err)
	}
	if !legacy.apps[newApp.ID].SyncConfirmed {
		t.Fatal("legacy-only decision not migrated")
	}
}

type losePolicyResponse struct {
	base http.RoundTripper
	path string
	lost bool
}

func (l *losePolicyResponse) RoundTrip(r *http.Request) (*http.Response, error) {
	res, err := l.base.RoundTrip(r)
	if err == nil && r.URL.Path == l.path && !l.lost {
		l.lost = true
		res.Body.Close()
		return nil, errors.New("response lost after commit")
	}
	return res, err
}

func TestCommittedApprovalWithLostResponseIsNotDuplicated(t *testing.T) {
	s, api, _ := policyServer(t)
	c := loginPolicyClient(t, s, api)
	c.http = &http.Client{Transport: &losePolicyResponse{base: api.Client().Transport, path: "/api/rules"}}
	if _, err := c.Action(context.Background(), "rules", map[string]any{"target": "example.com", "action": "approve", "revision": c.config.Profile.Revision}); err == nil {
		t.Fatal("expected lost response")
	}
	if len(c.config.Pinned) != 1 {
		t.Fatal("unconfirmed rule disappeared")
	}
	if err := c.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(c.config.Pinned) != 0 || len(c.config.Profile.Rules) != 1 || c.config.Profile.Revision != 2 {
		t.Fatal("acknowledged rule retried or duplicated")
	}
}

func TestOldServerKeepsLocalApplicationDecisionAndReportsMissingBackup(t *testing.T) {
	c := testTrafficClient(t)
	c.config.Profile.Token = "legacy"
	app := policyApp(c, "a")
	observe(t, c, "example.com", app, time.Now())
	c.config.Disabled = true
	out, err := c.Action(context.Background(), "applications", map[string]any{"id": app.ID, "decision": "addresses"})
	if err != nil || out.(map[string]any)["pending"] != true {
		t.Fatal(out, err)
	}
	if c.pendingPolicyCountLocked() != 1 || !strings.Contains(c.policySyncError, "обновите сервер") {
		t.Fatal("unsupported backup reported as saved")
	}
	raw, err := os.ReadFile(filepath.Join(c.dir, "applications.json"))
	if err != nil {
		t.Fatal(err)
	}
	var saved map[string]model.Application
	if err = json.Unmarshal(raw, &saved); err != nil || saved[app.ID].Decision != "addresses" {
		t.Fatal("local choice lost", err)
	}
}

func TestRestoredTrustConfiguresTunnelAndRemoteChangeClosesOnlyAffectedFlow(t *testing.T) {
	s, api, _ := policyServer(t)
	first := loginPolicyClient(t, s, api)
	app := policyApp(first, "a")
	observe(t, first, "example.com", app, time.Now())
	ctx := context.Background()
	if _, err := first.Action(ctx, "applications", map[string]any{"id": app.ID, "decision": "trusted"}); err != nil {
		t.Fatal(err)
	}
	clean := loginPolicyClient(t, s, api)
	observe(t, clean, "example.com", app, time.Now())
	if err := clean.SetVPNEnabled(true); err != nil {
		t.Fatal(err)
	}
	if err := clean.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	if clean.routeLocked("example.com", app.ID) != policy.AppVPN {
		t.Fatal("restored decision never enabled application tunnel")
	}
	trusted, peer := net.Pipe()
	defer peer.Close()
	direct, directPeer := net.Pipe()
	defer directPeer.Close()
	clean.active[trusted] = activeFlow{Target: "example.com", AppID: app.ID, Route: policy.AppVPN}
	clean.active[direct] = activeFlow{Target: "other.example", Route: policy.Direct}
	if _, err := first.Action(ctx, "applications", map[string]any{"id": app.ID, "decision": "addresses"}); err != nil {
		t.Fatal(err)
	}
	if err := clean.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := peer.Read(make([]byte, 1)); err != io.EOF {
		t.Fatal("old trusted flow survived remote change", err)
	}
	if _, ok := clean.active[direct]; !ok {
		t.Fatal("unrelated direct flow interrupted")
	}
	if clean.config.Profile.AppUUID != "" || clean.routeLocked("example.com", app.ID) != policy.Direct {
		t.Fatal("revoked trust retained app tunnel")
	}
}

func TestApplicationPolicySaveFailureClosesStaleVPNFlow(t *testing.T) {
	c := testTrafficClient(t)
	app := policyApp(c, "a")
	observe(t, c, "example.com", app, time.Now())
	c.apps[app.ID] = model.Application{ApplicationInfo: app, Decision: "trusted", SyncConfirmed: true}
	p := model.Profile{Status: "active", UUID: secure.UUID(), AppUUID: secure.UUID(), Server: "127.0.0.1", Port: 443, PublicKey: secure.Token(), SNI: "example.com", ShortID: "12ab", Path: "/test", Revision: 1, ApplicationRules: []model.ApplicationRule{{ID: app.ID, Platform: app.Platform, Decision: "trusted"}}}
	if err := c.apply(p); err != nil {
		t.Fatal(err)
	}
	conn, peer := net.Pipe()
	defer peer.Close()
	c.active[conn] = activeFlow{Target: "example.com", AppID: app.ID, Route: policy.AppVPN}
	if err := os.Remove(filepath.Join(c.dir, "applications.json")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(c.dir, "applications.json"), 0700); err != nil {
		t.Fatal(err)
	}
	p.Revision++
	p.ApplicationRules = []model.ApplicationRule{{ID: app.ID, Platform: app.Platform, Decision: "addresses"}}
	if err := c.apply(p); err == nil {
		t.Fatal("expected disk failure")
	}
	if _, err := peer.Read(make([]byte, 1)); err != io.EOF {
		t.Fatal("save failure retained stale authenticated flow", err)
	}
	if c.ready {
		t.Fatal("failed save published ready state")
	}
}

func TestRejectedPendingAddressDoesNotPreventOtherPolicyBackups(t *testing.T) {
	s, api, _ := policyServer(t)
	c := loginPolicyClient(t, s, api)
	c.config.Pinned = []string{"127.0.0.1", "example.com"}
	app := policyApp(c, "a")
	c.apps[app.ID] = model.Application{ApplicationInfo: app, Decision: "trusted", SyncPending: true}
	if err := c.syncSavedPolicy(context.Background()); err == nil {
		t.Fatal("invalid address unexpectedly saved")
	}
	if !policy.Approved(c.config.Profile.Rules, "example.com") || !c.apps[app.ID].SyncConfirmed {
		t.Fatal("one invalid address blocked unrelated rules")
	}
	if len(c.config.Pinned) != 1 || c.config.Pinned[0] != "127.0.0.1" {
		t.Fatal("rejected decision silently disappeared")
	}
}
