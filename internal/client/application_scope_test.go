package client

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jEUGENEdev/vpn/internal/model"
)

type scopeRecorder struct {
	calls int
	all   bool
	apps  []model.ApplicationInfo
	apply func(bool, []model.ApplicationInfo) error
}

func TestNativeScopeProfileRestoreAndCatalogue(t *testing.T) {
	c := testTrafficClient(t)
	c.identity.Platform = "android"
	a := model.ApplicationInfo{ID: strings.Repeat("a", 64), Name: "Approved", Path: "example.allowed", Platform: "android"}
	b := model.ApplicationInfo{ID: strings.Repeat("b", 64), Name: "Unapproved", Path: "example.denied", Platform: "android"}
	c.config.Profile.ApplicationRules = []model.ApplicationRule{{ID: a.ID, Platform: "android", Decision: "trusted"}}
	if err := c.SetInstalledApplications([]model.ApplicationInfo{a, b}); err != nil {
		t.Fatal(err)
	}
	if c.apps[a.ID].Decision != "trusted" || c.apps[b.ID].Decision != "pending" || len(c.observed) != 0 {
		t.Fatal("inventory did not restore consent without inventing traffic")
	}
	r := &scopeRecorder{}
	c.SetNetworkController(r)
	p := c.config.Profile
	p.ApplicationRules = []model.ApplicationRule{{ID: a.ID, Platform: "android", Decision: "denied"}, {ID: b.ID, Platform: "android", Decision: "addresses"}}
	// Even an incomplete/offline server profile must apply its saved native scope.
	_ = c.applyProfile(p, nil)
	if r.calls == 0 || len(r.apps) != 1 || r.apps[0].ID != b.ID {
		t.Fatal("server consent not applied to Android", r)
	}
	replacement := b
	replacement.ID = strings.Repeat("c", 64)
	if err := c.SetInstalledApplications([]model.ApplicationInfo{a, replacement}); err != nil {
		t.Fatal(err)
	}
	if len(r.apps) != 0 || c.apps[replacement.ID].Decision != "pending" {
		t.Fatal("different signer inherited package permission")
	}
	denied := c.apps[b.ID]
	denied.Decision, denied.SyncPending = "denied", true
	c.apps[b.ID] = denied
	if err := c.SetInstalledApplications([]model.ApplicationInfo{a, b}); err != nil {
		t.Fatal(err)
	}
	if c.apps[b.ID].Decision != "denied" || !c.apps[b.ID].SyncPending || len(r.apps) != 0 {
		t.Fatal("reinstall lost unsynced denial")
	}
	before := len(c.apps)
	if err := c.SetInstalledApplications([]model.ApplicationInfo{a, a}); err == nil || len(c.apps) != before {
		t.Fatal("invalid inventory partially applied")
	}
}

func TestNativeScopeFullModeFailureKeepsSelectiveIntent(t *testing.T) {
	c := testTrafficClient(t)
	r := &scopeRecorder{apply: func(all bool, apps []model.ApplicationInfo) error { return errors.New("native failure") }}
	c.SetNetworkController(r)
	if err := c.SetTrafficMode(TrafficAll); err == nil || c.trafficModeLocked() != TrafficSelective {
		t.Fatal("failed device-wide capture persisted full mode")
	}
}

func (*scopeRecorder) Check(bool) error { return nil }
func (*scopeRecorder) Apply(bool) error { return nil }
func (r *scopeRecorder) ApplyApplicationScope(all bool, apps []model.ApplicationInfo) error {
	r.calls++
	if r.apply != nil {
		if err := r.apply(all, apps); err != nil {
			return err
		}
	}
	r.all, r.apps = all, apps
	return nil
}

func TestNativeScopeGrantMustCaptureBeforeConsent(t *testing.T) {
	c := testTrafficClient(t)
	app := testApp("a")
	c.apps[app.ID] = model.Application{ApplicationInfo: app, Decision: "pending"}
	r := &scopeRecorder{apply: func(all bool, apps []model.ApplicationInfo) error {
		if all || len(apps) != 1 || apps[0].ID != app.ID {
			t.Fatalf("wrong native scope: %v %+v", all, apps)
		}
		if c.apps[app.ID].Decision != "pending" {
			t.Fatal("grant persisted before Android captured the app")
		}
		return errors.New("native capture failed")
	}}
	c.SetNetworkController(r)
	_, err := c.applicationAction(context.Background(), map[string]any{"id": app.ID, "decision": "trusted"})
	if err == nil || r.calls == 0 || c.apps[app.ID].Decision != "pending" {
		t.Fatalf("native failure granted uncaptured app: calls=%d decision=%s err=%v", r.calls, c.apps[app.ID].Decision, err)
	}
}

func TestNativeScopeExcludesUnapprovedAppsAndUpdates(t *testing.T) {
	c := testTrafficClient(t)
	a, b := testApp("a"), testApp("b")
	c.apps[a.ID] = model.Application{ApplicationInfo: a, Decision: "pending"}
	c.apps[b.ID] = model.Application{ApplicationInfo: b, Decision: "denied"}
	r := &scopeRecorder{}
	c.SetNetworkController(r)
	if _, err := c.applicationAction(context.Background(), map[string]any{"id": a.ID, "decision": "addresses"}); err != nil {
		t.Fatal(err)
	}
	if r.calls == 0 || r.all || len(r.apps) != 1 || r.apps[0].ID != a.ID {
		t.Fatalf("unapproved app captured or no OS update: %+v", r)
	}
	if _, err := c.applicationAction(context.Background(), map[string]any{"id": a.ID, "decision": "denied"}); err != nil {
		t.Fatal(err)
	}
	if r.all || len(r.apps) != 0 {
		t.Fatal("revoked app still in native scope", r)
	}
	if err := c.SetTrafficMode(TrafficAll); err != nil {
		t.Fatal(err)
	}
	if !r.all {
		t.Fatal("full mode did not capture every app")
	}
	if err := c.SetTrafficMode(TrafficSelective); err != nil {
		t.Fatal(err)
	}
	if r.all || len(r.apps) != 0 {
		t.Fatal("return to selective retained global VPN")
	}
}

func TestNativeScopeFailedSaveNeverReleasesProtectedApps(t *testing.T) {
	c := testTrafficClient(t)
	a := testApp("a")
	c.apps[a.ID] = model.Application{ApplicationInfo: a, Decision: "trusted"}
	r := &scopeRecorder{apply: func(all bool, apps []model.ApplicationInfo) error {
		if !all && (len(apps) != 1 || apps[0].ID != a.ID) {
			t.Fatal("native exclusion before saved revocation")
		}
		return nil
	}}
	c.SetNetworkController(r)
	if err := os.Mkdir(filepath.Join(c.dir, "applications.json"), 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := c.applicationAction(context.Background(), map[string]any{"id": a.ID, "decision": "denied"}); err == nil {
		t.Fatal("expected save failure")
	}
	if c.apps[a.ID].Decision != "trusted" {
		t.Fatal("save failure changed consent")
	}
}
