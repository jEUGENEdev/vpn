package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestPublicAdminConfigurationPreservesServerIdentity(t *testing.T) {
	path := filepath.Join(t.TempDir(), "server.json")
	original := []byte(`{"address":":8443","public_ip":"8.8.8.8","database":"/var/lib/linevpn/server.db","admin_address":"127.0.0.1:8444","transport":{"port":443,"path":"/unchanged","private_key":"synthetic-key"},"future_field":{"retain":true}}`)
	if err := os.WriteFile(path, original, 0600); err != nil {
		t.Fatal(err)
	}
	var before map[string]any
	if err := json.Unmarshal(original, &before); err != nil {
		t.Fatal(err)
	}
	for _, enabled := range []bool{true, false} {
		changed, err := setPublicAdmin(path, enabled)
		if err != nil || !changed {
			t.Fatal("visibility update failed", changed, err)
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var after map[string]any
		if err := json.Unmarshal(raw, &after); err != nil {
			t.Fatal(err)
		}
		if after["public_admin"] != enabled {
			t.Fatal("wrong visibility")
		}
		delete(after, "public_admin")
		if !reflect.DeepEqual(before, after) {
			t.Fatal("configuration update changed server identity or unrelated fields")
		}
		if changed, err := setPublicAdmin(path, enabled); err != nil || changed {
			t.Fatal("configuration update is not idempotent", err)
		}
	}
}

func TestPublicAdminConfigurationRejectsInvalidInputWithoutWriting(t *testing.T) {
	for _, raw := range []string{`null`, `{`, `{"public_ip":"127.0.0.1"}`} {
		path := filepath.Join(t.TempDir(), "server.json")
		if err := os.WriteFile(path, []byte(raw), 0600); err != nil {
			t.Fatal(err)
		}
		if changed, err := setPublicAdmin(path, true); err == nil || changed {
			t.Fatal("invalid configuration accepted")
		}
		after, err := os.ReadFile(path)
		if err != nil || string(after) != raw {
			t.Fatal("invalid configuration was modified", err)
		}
	}
}
