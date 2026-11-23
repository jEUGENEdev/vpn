package client

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jEUGENEdev/vpn/internal/model"
	"github.com/jEUGENEdev/vpn/internal/policy"
	"github.com/jEUGENEdev/vpn/internal/secure"
)

func TestSyncAppliesTransportChangesWithoutPolicyRevision(t *testing.T) {
	changes := map[string]func(*model.Profile){
		"server":     func(p *model.Profile) { p.Server = "127.0.0.2" },
		"port":       func(p *model.Profile) { p.Port = 8443 },
		"SNI":        func(p *model.Profile) { p.SNI = "new.example.com" },
		"public key": func(p *model.Profile) { p.PublicKey = secure.Token() },
		"short ID":   func(p *model.Profile) { p.ShortID = "34cd" },
		"XHTTP path": func(p *model.Profile) { p.Path = "/new-path" },
	}
	for name, change := range changes {
		for _, disabled := range []bool{false, true} {
			mode := "enabled"
			if disabled {
				mode = "disabled"
			}
			t.Run(name+"/"+mode, func(t *testing.T) {
				c := testTrafficClient(t)
				c.config.Disabled = disabled
				c.config.API = "https://control.example.com"
				app := testApp("a")
				c.apps[app.ID] = model.Application{ApplicationInfo: app, Decision: "trusted", SyncConfirmed: true}
				p := model.Profile{Status: "active", AccountID: "account", Token: "test-token", UUID: secure.UUID(), AppUUID: secure.UUID(), Server: "127.0.0.1", Port: 443, PublicKey: secure.Token(), SNI: "example.com", ShortID: "12ab", Path: "/test", Rules: []string{"example.com"}, Revision: 7}
				if err := c.apply(p); err != nil {
					t.Fatal(err)
				}
				var peers []net.Conn
				if !disabled {
					for _, route := range []policy.Route{policy.VPN, policy.AppVPN} {
						left, right := net.Pipe()
						t.Cleanup(func() { right.Close() })
						info := activeFlow{Target: "example.com", Route: route}
						if route == policy.AppVPN {
							info.AppID = app.ID
						}
						c.active[left] = info
						peers = append(peers, right)
					}
				}
				direct, peer := net.Pipe()
				t.Cleanup(func() { peer.Close() })
				c.active[direct] = activeFlow{Target: "direct.example.org", Route: policy.Direct}
				change(&p)
				response := p
				response.Token = "" // Sync does not reissue the device token.
				c.http = &http.Client{Transport: syncRoundTripper(func(r *http.Request) (*http.Response, error) {
					if r.Method != "GET" || r.URL.Path != "/api/sync" {
						t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
					}
					raw, _ := json.Marshal(syncResult{Profile: response})
					return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(string(raw)))}, nil
				})}
				if err := c.Sync(context.Background()); err != nil {
					t.Fatal(err)
				}
				if !reflect.DeepEqual(c.config.Profile, p) {
					t.Fatal("transport change ignored because account policy revision stayed the same")
				}
				var saved Config
				raw, err := os.ReadFile(filepath.Join(c.dir, "profile.json"))
				if err != nil || json.Unmarshal(raw, &saved) != nil || !reflect.DeepEqual(saved.Profile, p) {
					t.Fatal("updated transport did not survive persistence")
				}
				if c.config.Disabled != disabled || (disabled && c.ready) {
					t.Fatal("transport refresh changed the user's power intent")
				}
				for _, peer := range peers {
					peer.SetReadDeadline(time.Now().Add(time.Second))
					if _, err := peer.Read(make([]byte, 1)); err != io.EOF {
						t.Fatal("stale protected connection survived transport replacement", err)
					}
				}
				if _, ok := c.active[direct]; !ok {
					t.Fatal("refresh closed an unrelated direct connection")
				}
				epoch := c.routeEpoch
				if err := c.Sync(context.Background()); err != nil || c.routeEpoch != epoch {
					t.Fatal("unchanged sync reapplied transport", err)
				}
			})
		}
	}
}
