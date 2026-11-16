package server

import (
	"bytes"
	"encoding/json"
	"github.com/jEUGENEdev/vpn/internal/model"
	"github.com/jEUGENEdev/vpn/internal/secure"
	"github.com/jEUGENEdev/vpn/internal/store"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"
)

func TestAppTunnelAndFailureReportsAreDeviceScoped(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	st.Update(func(v *store.State) error {
		v.Accounts["a"] = store.Account{Account: model.Account{ID: "a", Status: "active", Rules: []string{"allowed.example"}}}
		for _, id := range []string{"one", "two"} {
			v.Devices[id] = store.Device{Device: model.Device{ID: id, AccountID: "a", Expires: time.Now().Add(time.Hour)}, Hash: secure.Hash(id), Secret: secure.UUID()}
		}
		return nil
	})
	s, err := New(st, Config{PublicIP: "8.8.8.8"}, "admin-password-long-enough", func(store.State) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	call := func(method, path, token string, input any, status int) map[string]json.RawMessage {
		t.Helper()
		raw, _ := json.Marshal(input)
		r := httptest.NewRequest(method, path, bytes.NewReader(raw))
		r.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		s.Handler(nil).ServeHTTP(w, r)
		if w.Code != status {
			t.Fatalf("%s returned %d: %s", path, w.Code, w.Body.String())
		}
		var out map[string]json.RawMessage
		json.Unmarshal(w.Body.Bytes(), &out)
		return out
	}
	call("POST", "/api/app-vpn", "", map[string]bool{"enabled": true}, 401)
	profile := call("POST", "/api/app-vpn", "one", map[string]bool{"enabled": true}, 200)
	var first, primary string
	json.Unmarshal(profile["app_uuid"], &first)
	json.Unmarshal(profile["uuid"], &primary)
	if first == "" || first == primary {
		t.Fatal("app traffic reused address credential")
	}
	st.View(func(v store.State) error {
		if v.Devices["two"].AppSecret != "" || len(v.Accounts["a"].Rules) != 1 {
			t.Fatal("app trust widened other device or account rules")
		}
		return nil
	})
	call("POST", "/api/app-vpn", "one", map[string]any{"enabled": true, "id": "two"}, 400)
	call("POST", "/api/app-vpn", "one", map[string]bool{"enabled": false}, 200)
	profile = call("POST", "/api/app-vpn", "one", map[string]bool{"enabled": true}, 200)
	var second string
	json.Unmarshal(profile["app_uuid"], &second)
	if first == second {
		t.Fatal("disabled credential reused")
	}
	call("POST", "/api/discover", "one", map[string]any{"targets": []string{"working.example.com"}, "failed_targets": []string{"api.example.com"}}, 200)
	call("POST", "/api/discover", "two", map[string]any{"failed_targets": []string{"api.example.com"}}, 200)
	failed := func(token string) []string {
		out := call("GET", "/api/sync", token, nil, 200)
		var requests []model.Request
		json.Unmarshal(out["requests"], &requests)
		targets := []string{}
		for _, r := range requests {
			if r.FailedDevices != nil {
				t.Fatal("other device report metadata exposed")
			}
			if r.DirectFailed {
				targets = append(targets, r.Target)
			}
		}
		return targets
	}
	if got := failed("one"); len(got) != 1 || got[0] != "api.example.com" {
		t.Fatal(got)
	}
	call("POST", "/api/discover", "one", map[string]any{"resolved_targets": []string{"api.example.com"}}, 200)
	if len(failed("one")) != 0 || len(failed("two")) != 1 {
		t.Fatal("one device's recovery removed another device's failure")
	}
	call("POST", "/api/dismiss", "two", map[string]string{"target": "example.com"}, 200)
	call("POST", "/api/discover", "two", map[string]any{"failed_targets": []string{"fresh.example.com"}}, 200)
	if len(failed("two")) != 0 {
		t.Fatal("new subdomain escaped parent dismissal")
	}
	st.Update(func(v *store.State) error { d := v.Devices["one"]; d.Revoked = true; v.Devices["one"] = d; return nil })
	call("POST", "/api/app-vpn", "one", map[string]bool{"enabled": true}, 401)
}
