package client

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/jEUGENEdev/vpn/internal/model"
	"github.com/jEUGENEdev/vpn/internal/transport"
)

// Installers keep the state directory outside their payload. Opening those
// existing files with the replacement client must retain identity and choices.
func TestUpgradeLoadsExistingIdentityAndDecisions(t *testing.T) {
	for _, disabled := range []bool{false, true} {
		t.Run(map[bool]string{false: "enabled", true: "disabled"}[disabled], func(t *testing.T) {
			dir := t.TempDir()
			want := Config{
				Disabled: disabled, API: "https://127.0.0.1:8443", Pin: "fixture-pin", BootstrapKey: "fixture-bootstrap",
				Pinned: []string{"pending.example", "192.0.2.1", "2001:db8::1"},
				Profile: model.Profile{AccountID: "existing-account", DeviceID: "existing-device", Login: "fixture",
					Token: "fixture-token", UUID: "existing-transport", AppUUID: "existing-app-transport",
					Rules: []string{"approved.example"}, Revision: 42},
			}
			apps := map[string]model.Application{}
			for i, decision := range []string{"trusted", "addresses", "pending"} {
				id := strings.Repeat(string(rune('a'+i)), 64)
				apps[id] = model.Application{ApplicationInfo: model.ApplicationInfo{ID: id, Name: "Fixture", Path: "/fixture", Platform: "darwin"}, Decision: decision}
			}
			for name, value := range map[string]any{"profile.json": want, "applications.json": apps} {
				raw, err := json.Marshal(value)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(dir, name), raw, 0600); err != nil {
					t.Fatal(err)
				}
			}
			// Both initial replacement and repeated installation read the same state.
			for cycle := 0; cycle < 2; cycle++ {
				c, err := New(dir, &transport.Dialer{})
				if err != nil {
					t.Fatal(err)
				}
				if !reflect.DeepEqual(c.config, want) || !reflect.DeepEqual(c.apps, apps) {
					c.Close()
					t.Fatal("replacement client changed profile, identity or decisions")
				}
				c.Close()
			}
		})
	}
}
