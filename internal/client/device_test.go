package client

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/jEUGENEdev/vpn/internal/model"
	"github.com/jEUGENEdev/vpn/internal/transport"
)

func TestNativeDeviceNameCannotBeOverriddenByUI(t *testing.T) {
	var received map[string]any
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&received)
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"select_device":true,"devices":[]}`))
	}))
	defer api.Close()
	c, err := New(t.TempDir(), &transport.Dialer{})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.http, c.config.API = api.Client(), api.URL
	c.identity = DeviceIdentity{Name: "Actual computer", Platform: "darwin"}
	c.config.Profile.DeviceID = "current-device"
	input := map[string]any{"name": "Forged", "platform": "android", "device_id": "foreign", "new_device": true}
	_, err = c.Auth(context.Background(), "login", input)
	if err != nil {
		t.Fatal(err)
	}
	if received["name"] != "Actual computer" || received["platform"] != "darwin" || received["device_id"] != "current-device" || received["new_device"] != nil {
		t.Fatal(received)
	}
	if input["name"] != "Forged" {
		t.Fatal("Auth mutated caller input")
	}
	c.identity.Name = ""
	c.config.Profile.DeviceID = ""
	_, err = c.Auth(context.Background(), "login", map[string]any{"device_id": "selected"})
	if err != nil || received["device_id"] != "selected" || received["name"] != "" {
		t.Fatal(received, err)
	}
	if c.config.Profile.Token != "" {
		t.Fatal("selection created a profile")
	}
}

func TestDeviceNameValidation(t *testing.T) {
	for _, name := range []string{"", "  ", "unknown", "localhost", "android", "bad\nname", "bad\x00name"} {
		if cleanDeviceName(name) != "" {
			t.Fatalf("accepted unavailable name %q", name)
		}
	}
	name := cleanDeviceName(strings.Repeat("Я", 100))
	if !utf8.ValidString(name) || len(name) > 80 || len(name) == 0 {
		t.Fatal("invalid UTF-8 truncation")
	}
	if cleanDeviceName("  Samsung SM-S948B  ") != "Samsung SM-S948B" {
		t.Fatal("native name changed")
	}
}

func TestSelfDeletionErasesLocalKeysButKeepsProtection(t *testing.T) {
	syncCalls := 0
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/sync" {
			syncCalls++
			w.WriteHeader(401)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"ok":true}`))
	}))
	defer api.Close()
	dir := t.TempDir()
	c, err := New(dir, &transport.Dialer{})
	if err != nil {
		t.Fatal(err)
	}
	c.http, c.config.API = api.Client(), api.URL
	c.config.Profile = model.Profile{AccountID: "a", DeviceID: "self", Token: "deleted-secret", UUID: "deleted-vless", AppUUID: "deleted-app-secret", Rules: []string{"example.com"}}
	c.config.Pinned = []string{"example.org"}
	c.devices = []model.Device{{ID: "self"}}
	c.ready = true
	_, err = c.Action(context.Background(), "revoke", map[string]any{"id": "self"})
	if err != nil {
		t.Fatal("successful deletion reported as error:", err)
	}
	if syncCalls != 0 || c.status != "auth_required" || c.ready || len(c.devices) != 0 {
		t.Fatal("invalid state after self deletion")
	}
	raw, err := os.ReadFile(filepath.Join(dir, "profile.json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "deleted-") {
		t.Fatal("deleted credentials remain on disk")
	}
	c.Close()
	restarted, err := New(dir, &transport.Dialer{})
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close()
	if restarted.status != "auth_required" {
		t.Fatal("restart lost reauthentication state")
	}
	for _, target := range []string{"example.com", "example.org"} {
		if conn, err := restarted.Dial(context.Background(), "tcp", target, 443); err == nil {
			conn.Close()
			t.Fatal("deletion bypassed protected route")
		}
	}
}

func TestVPNPowerCannotHideRequiredReauthentication(t *testing.T) {
	c, err := New(t.TempDir(), &transport.Dialer{})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.config.Profile = model.Profile{AccountID: "a", DeviceID: "deleted", Status: "auth_required", Rules: []string{"example.com"}}
	c.status = "auth_required"
	for _, enabled := range []bool{false, true, false} {
		if err := c.SetVPNEnabled(enabled); err != nil {
			t.Fatal(err)
		}
		state := c.State().(map[string]any)
		if state["auth_required"] != true {
			t.Fatalf("power %v hid revoked session: %v", enabled, state["status"])
		}
	}
}
