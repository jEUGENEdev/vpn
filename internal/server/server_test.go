package server

import (
	"bytes"
	"encoding/json"
	"github.com/jEUGENEdev/vpn/internal/model"
	"github.com/jEUGENEdev/vpn/internal/store"
	"github.com/jEUGENEdev/vpn/internal/transport"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"
)

func TestAccountLifecycle(t *testing.T) {
	st, e := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if e != nil {
		t.Fatal(e)
	}
	defer st.Close()
	applied := 0
	s, e := New(st, Config{PublicIP: "8.8.8.8", Transport: transport.ServerOptions{Port: 443}}, "admin-password-very-long", func(store.State) error { applied++; return nil })
	if e != nil {
		t.Fatal(e)
	}
	h := s.Handler(nil)
	call := func(path, token string, input any, want int) map[string]any {
		t.Helper()
		raw, _ := json.Marshal(input)
		method := "POST"
		if input == nil {
			method = "GET"
		}
		r := httptest.NewRequest(method, path, bytes.NewReader(raw))
		r.RemoteAddr = "127.0.0.1:1234"
		r.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != want {
			t.Fatalf("%s: %d want %d: %s", path, w.Code, want, w.Body.String())
		}
		var out map[string]any
		json.Unmarshal(w.Body.Bytes(), &out)
		return out
	}
	cred := map[string]any{"login": "alice", "password": "some-strong-password", "name": "Laptop", "platform": "windows"}
	call("/api/register", "", cred, 202)
	call("/api/login", "", cred, 403)
	call("/api/admin/accounts", "", nil, 401)
	adm := call("/api/admin/login", "", map[string]string{"password": "admin-password-very-long"}, 200)["token"].(string)
	list := call("/api/admin/accounts", adm, nil, 200)
	account := list["accounts"].([]any)[0].(map[string]any)["id"].(string)
	call("/api/admin/account", adm, map[string]string{"id": account, "status": "active"}, 200)
	p := call("/api/login", "", cred, 200)
	token := p["token"].(string)
	device := p["device_id"].(string)
	call("/api/discover", token, map[string]any{"targets": []string{"api.example.com", "api.example.com"}}, 200)
	sync := call("/api/sync", token, nil, 200)
	if len(sync["requests"].([]any)) != 1 {
		t.Fatal("dedup")
	}
	rev := sync["profile"].(map[string]any)["revision"]
	call("/api/rules", token, map[string]any{"target": "example.com", "action": "approve", "revision": rev}, 200)
	call("/api/rules", token, map[string]any{"target": "other.com", "action": "approve", "revision": rev}, 409)
	sync = call("/api/sync", token, nil, 200)
	if len(sync["requests"].([]any)) != 0 {
		t.Fatal("inheritance")
	}
	// A device can dismiss its local discovery before its first sync upload.
	call("/api/dismiss", token, map[string]string{"target": "Fresh.Example.org."}, 200)
	call("/api/discover", token, map[string]any{"targets": []string{"fresh.example.org"}}, 200)
	sync = call("/api/sync", token, nil, 200)
	if len(sync["requests"].([]any)) != 0 || len(sync["dismissed"].([]any)) != 1 || sync["dismissed"].([]any)[0] != "fresh.example.org" {
		t.Fatal("dismissal before discovery was lost")
	}
	code := call("/api/pair", token, map[string]any{}, 200)["code"].(string)
	paired := call("/api/pair/claim", "", map[string]string{"code": code, "name": "Phone", "platform": "android"}, 200)
	call("/api/pair/claim", "", map[string]string{"code": code, "name": "Phone2", "platform": "android"}, 401)
	if len(paired["rules"].([]any)) != 1 {
		t.Fatal("account policy not shared")
	}
	call("/api/admin/revoke", adm, map[string]string{"id": device}, 200)
	call("/api/sync", token, nil, 401)
	call("/api/admin/account", adm, map[string]string{"id": account, "status": "blocked"}, 200)
	call("/api/sync", paired["token"].(string), nil, 401)
	if applied < 5 {
		t.Fatal("data plane not updated")
	}
	st.View(func(v store.State) error {
		for _, d := range v.Devices {
			if d.Hash == token || d.Secret == "" {
				t.Fatal("credentials persistence")
			}
		}
		return nil
	})
	_ = http.MethodPost
}
func TestAccountIsolation(t *testing.T) {
	st, _ := store.Open(filepath.Join(t.TempDir(), "state.db"))
	defer st.Close()
	s, _ := New(st, Config{}, "admin-password-very-long", nil)
	st.Update(func(v *store.State) error {
		v.Accounts["a"] = store.Account{Account: model.Account{ID: "a", Status: "active"}}
		v.Accounts["b"] = store.Account{Account: model.Account{ID: "b", Status: "active"}}
		return nil
	})
	a, e := s.enroll("a", "a", "android")
	if e != nil {
		t.Fatal(e)
	}
	b, e := s.enroll("b", "b", "android")
	if e != nil {
		t.Fatal(e)
	}
	raw, _ := json.Marshal(map[string]string{"id": b.DeviceID})
	req := httptest.NewRequest("POST", "/api/revoke", bytes.NewReader(raw))
	req.Header.Set("Authorization", "Bearer "+a.Token)
	w := httptest.NewRecorder()
	s.Handler(nil).ServeHTTP(w, req)
	if w.Code != 403 {
		t.Fatal(w.Code)
	}
	st.View(func(v store.State) error {
		if v.Devices[b.DeviceID].Revoked {
			t.Fatal("cross-account revocation")
		}
		return nil
	})
	_ = time.Second
}

func TestExpiryOnlyReconfiguresOnce(t *testing.T) {
	st, e := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if e != nil {
		t.Fatal(e)
	}
	defer st.Close()
	now := time.Now()
	st.Update(func(v *store.State) error {
		v.Devices["expired"] = store.Device{Device: model.Device{ID: "expired", Expires: now.Add(-time.Second)}}
		v.Devices["valid"] = store.Device{Device: model.Device{ID: "valid", Expires: now.Add(time.Hour)}}
		return nil
	})
	applied := 0
	s, e := New(st, Config{}, "admin-password-very-long", func(v store.State) error {
		applied++
		if !v.Devices["expired"].Revoked || v.Devices["valid"].Revoked {
			t.Fatal("incorrect revocation")
		}
		return nil
	})
	if e != nil {
		t.Fatal(e)
	}
	if e = s.Expire(now); e != nil {
		t.Fatal(e)
	}
	if e = s.Expire(now.Add(time.Minute)); e != nil {
		t.Fatal(e)
	}
	if applied != 1 {
		t.Fatalf("transport reconfigured %d times", applied)
	}
}
