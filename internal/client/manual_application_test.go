package client

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/jEUGENEdev/vpn/internal/model"
)

func TestManuallyAddedApplicationBeforeTraffic(t *testing.T) {
	c := testTrafficClient(t)
	app := testApp("a")
	app.Platform, app.Path = runtime.GOOS, filepath.Join(t.TempDir(), "Browser.exe")
	h := c.Handler("private", http.NotFoundHandler())
	add := func() model.Application {
		body, _ := json.Marshal(app)
		req := httptest.NewRequest("POST", "/local/applications/add", strings.NewReader(string(body)))
		req.Header.Set("Authorization", "Bearer private")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != 200 {
			t.Fatalf("manual addition failed: %d %s", w.Code, w.Body.String())
		}
		var result model.Application
		if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		return result
	}
	first := add()
	if first.ID != app.ID || first.Decision != "pending" || first.Target != "" || !first.LastSeen.IsZero() {
		t.Fatalf("selection fabricated traffic or granted VPN: %+v", first)
	}
	if _, err := c.applicationAction(t.Context(), map[string]any{"id": app.ID, "decision": "addresses"}); err != nil {
		t.Fatal(err)
	}
	observe(t, c, "example.com", app, time.Now())
	if again := add(); again.Decision != "addresses" || again.Target != "example.com" || !first.FirstSeen.Equal(again.FirstSeen) {
		t.Fatalf("re-selection discarded a decision or observation: %+v", again)
	}
	if len(c.apps) != 1 || !c.applicationAllowedLocked(app.ID) || c.applicationAllowedLocked("") {
		t.Fatal("automatic attribution did not reuse the selected identity")
	}
	c.apps = nil
	if err := c.loadApplications(); err != nil || c.apps[app.ID].Decision != "addresses" {
		t.Fatal("manual decision did not persist", err)
	}
}

type packagePicker struct {
	scopeRecorder
	packageInfo model.ApplicationInfo
}

func (p *packagePicker) InstalledPackage(name string) (model.ApplicationInfo, error) {
	if name == "missing.package" {
		return model.ApplicationInfo{}, errors.New("not installed")
	}
	return p.packageInfo, nil
}

func TestManualPackageUsesNativeIdentityAndPreservesScope(t *testing.T) {
	c := testTrafficClient(t)
	c.identity.Platform = "android"
	existing := model.ApplicationInfo{ID: strings.Repeat("a", 64), Platform: "android", Path: "existing.package", Name: "Existing"}
	picked := model.ApplicationInfo{ID: strings.Repeat("b", 64), Platform: "android", Path: "selected.package", Name: "Selected"}
	c.config.Profile.ApplicationRules = []model.ApplicationRule{{ID: existing.ID, Platform: "android", Decision: "trusted"}}
	if err := c.SetInstalledApplications([]model.ApplicationInfo{existing}); err != nil {
		t.Fatal(err)
	}
	p := &packagePicker{packageInfo: picked}
	c.SetNetworkController(p)
	// Adding a pending package must work while the tunnel is unavailable.
	p.apply = func(bool, []model.ApplicationInfo) error { return errors.New("offline") }
	added, err := c.addAndroidPackage(picked.Path)
	if err != nil || added.ID != picked.ID || added.Decision != "pending" || !added.LastSeen.IsZero() {
		t.Fatal("package was not safely added before traffic", err)
	}
	if !c.appInventory[existing.ID] || !c.appInventory[picked.ID] || len(c.observed) != 0 || p.calls != 0 {
		t.Fatal("selection changed another package or restarted the VPN")
	}
	for _, name := range []string{"missing.package", "wrong.package"} {
		if _, err := c.addAndroidPackage(name); err == nil {
			t.Fatal("unverified package accepted", name)
		}
	}
	p.apply = nil
	if _, err = c.applicationAction(t.Context(), map[string]any{"id": picked.ID, "decision": "addresses"}); err != nil {
		t.Fatal(err)
	}
	if _, err = c.addAndroidPackage(picked.Path); err != nil || c.apps[picked.ID].Decision != "addresses" {
		t.Fatal("re-select discarded choice", err)
	}
	p.packageInfo.ID = strings.Repeat("c", 64)
	newApp, err := c.addAndroidPackage(picked.Path)
	if err != nil || newApp.Decision != "pending" || c.appInventory[picked.ID] || !c.appInventory[existing.ID] {
		t.Fatal("new signer inherited permissions", err)
	}
	_, scope := c.ApplicationScope()
	if len(scope) != 1 || scope[0].ID != existing.ID {
		t.Fatal("incorrect native scope", scope)
	}
}
