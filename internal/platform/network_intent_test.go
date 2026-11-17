//go:build !android

package platform

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestStartupOnlyRemovesProtectionForPersistedOff(t *testing.T) {
	for _, tc := range []struct {
		name, profile string
		off, invalid  bool
	}{
		{"missing", "", false, false},
		{"old-profile", `{}`, false, false},
		{"enabled", `{"vpn_disabled":false}`, false, false},
		{"disabled", `{"vpn_disabled":true}`, true, false},
		{"corrupt", `{`, false, true},
		{"wrong-type", `{"vpn_disabled":"true"}`, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if tc.profile != "" {
				if err := os.WriteFile(filepath.Join(dir, "profile.json"), []byte(tc.profile), 0600); err != nil {
					t.Fatal(err)
				}
			}
			guarded, recovered := false, false
			err := prepareNetwork(dir, func(name string) error {
				if name != "" {
					t.Fatal(name)
				}
				guarded = true
				return nil
			}, func(string) error { recovered = true; return nil })
			if guarded == tc.off || recovered != tc.off || (err != nil) != tc.invalid {
				t.Fatalf("guard=%v recovery=%v err=%v", guarded, recovered, err)
			}
		})
	}
}

func TestGuardFailureNeverRunsRecovery(t *testing.T) {
	want := errors.New("firewall unavailable")
	err := prepareNetwork(t.TempDir(), func(string) error { return want }, func(string) error { t.Fatal("failure removed protection"); return nil })
	if !errors.Is(err, want) {
		t.Fatal(err)
	}
}

func TestPFGuardBlocksBothFamiliesOutsideAgentAndTunnel(t *testing.T) {
	for _, iface := range []string{"", "utun8"} {
		rules, err := guardRules(iface)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.HasSuffix(rules, "block drop out quick all\n") || !strings.Contains(rules, "user _linevpn") {
			t.Fatal(rules)
		}
		if strings.Contains(rules, "on utun8") != (iface != "") {
			t.Fatal("wrong tunnel exception", rules)
		}
		if strings.Contains(rules, "user root") {
			t.Fatal("all root apps bypass protection")
		}
	}
	for _, iface := range []string{"en0", "utun", "utun1\npass out all", "utun-1"} {
		if _, err := guardRules(iface); err == nil {
			t.Fatal("unsafe interface", iface)
		}
	}
}
