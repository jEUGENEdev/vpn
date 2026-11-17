package server

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jEUGENEdev/vpn/internal/model"
	"github.com/jEUGENEdev/vpn/internal/secure"
	"github.com/jEUGENEdev/vpn/internal/store"
)

type authFixture struct {
	s       *Server
	key     string
	applied int
	t       *testing.T
}

func newAuthFixture(t *testing.T) *authFixture {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	cert, _ := bootstrapCertificate(t, "8.8.8.8", time.Now().Add(time.Hour))
	path := filepath.Join(dir, "api.pem")
	if err = os.WriteFile(path, cert, 0600); err != nil {
		t.Fatal(err)
	}
	f := &authFixture{t: t}
	f.s, err = New(st, Config{PublicIP: "8.8.8.8", Address: ":8443", Cert: path}, "admin-password-very-long", func(store.State) error { f.applied++; return nil })
	if err != nil {
		t.Fatal(err)
	}
	f.s.admins[secure.Hash("admin")] = session{time.Now().Add(time.Hour)}
	st.View(func(v store.State) error { f.key = v.BootstrapKey; return nil })
	return f
}
func (f *authFixture) call(path, token string, input any, want int) map[string]any {
	f.t.Helper()
	raw, _ := json.Marshal(input)
	method := "POST"
	if input == nil {
		method = "GET"
	}
	r := httptest.NewRequest(method, path, bytes.NewReader(raw))
	r.Header.Set("Authorization", "Bearer "+token)
	r.Header.Set("X-LineVPN-Profile", f.key)
	w := httptest.NewRecorder()
	f.s.Handler(nil).ServeHTTP(w, r)
	if w.Code != want {
		f.t.Fatalf("%s: got %d want %d: %s", path, w.Code, want, w.Body.String())
	}
	var out map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		f.t.Fatal(err)
	}
	return out
}
func (f *authFixture) account() (string, string, map[string]any) {
	f.t.Helper()
	key := f.call("/api/register", "", map[string]string{"login": "Alice"}, 202)["access_key"].(string)
	var id string
	f.s.Store.View(func(v store.State) error {
		for _, a := range v.Accounts {
			id = a.ID
		}
		return nil
	})
	cred := map[string]any{"access_key": key, "name": "Laptop", "platform": "windows"}
	f.call("/api/login", "", cred, 403)
	f.call("/api/admin/account", "admin", map[string]string{"id": id, "status": "active"}, 200)
	return id, key, cred
}

func TestKeyAuthenticationAndAdministrativeRecovery(t *testing.T) {
	f := newAuthFixture(t)
	f.call("/api/register", "", map[string]string{"login": "legacy", "password": "some-strong-password"}, 400)
	id, key, cred := f.account()
	if !validAccessKey(key) {
		t.Fatal("invalid generated key")
	}
	p := f.call("/api/login", "", cred, 200)
	if p["login"] != "alice" {
		t.Fatal("account name missing")
	}
	token := p["token"].(string)
	paired := f.call("/api/pair", token, map[string]any{}, 200)["code"].(string)
	list := f.call("/api/admin/accounts", "admin", nil, 200)
	raw, _ := json.Marshal(list)
	if strings.Contains(string(raw), key) || strings.Contains(string(raw), "key_hash") || strings.Contains(string(raw), "password_hash") {
		t.Fatal("admin listing leaked a credential")
	}
	f.s.Store.View(func(v store.State) error {
		a := v.Accounts[id]
		if a.KeyHash != secure.Hash(key) || a.Hash != "" {
			t.Fatal("account did not store only key hash")
		}
		return nil
	})
	f.call("/api/login", "", map[string]string{"login": "alice", "password": "some-strong-password", "name": "Laptop", "platform": "windows"}, 400)
	f.call("/api/admin/access-key", token, map[string]any{"id": id, "confirm": true}, 401)
	f.call("/api/admin/access-key", "admin", map[string]any{"id": id}, 400)
	next := f.call("/api/admin/access-key", "admin", map[string]any{"id": id, "confirm": true}, 200)["access_key"].(string)
	if next == key {
		t.Fatal("key reused")
	}
	f.call("/api/login", "", cred, 401)
	f.call("/api/sync", token, nil, 401)
	f.call("/api/pair/claim", "", map[string]string{"code": paired, "name": "Phone", "platform": "android"}, 401)
	cred["access_key"] = next
	p = f.call("/api/login", "", cred, 200)
	if p["account_id"] != id || p["login"] != "alice" {
		t.Fatal("rotation replaced identity")
	}
	if f.applied < 3 {
		t.Fatal("revocation not applied to transport")
	}
	// Existing bcrypt accounts remain intact until an administrator issues a key.
	f.s.Store.Update(func(v *store.State) error {
		v.Accounts["old"] = store.Account{Account: model.Account{ID: "old", Login: "old-user", Status: "active", Rules: []string{"example.com"}, Revision: 7}, Hash: "legacy-bcrypt"}
		return nil
	})
	legacyKey := f.call("/api/admin/access-key", "admin", map[string]any{"id": "old", "confirm": true}, 200)["access_key"].(string)
	p = f.call("/api/login", "", map[string]string{"access_key": legacyKey, "name": "Phone", "platform": "android"}, 200)
	if p["account_id"] != "old" || p["login"] != "old-user" || len(p["rules"].([]any)) != 1 {
		t.Fatal("legacy migration lost account policy")
	}
}

func TestSelfKeyRotationRevokesEveryDeviceAndCannotCrossAccounts(t *testing.T) {
	f := newAuthFixture(t)
	id, _, cred := f.account()
	p := f.call("/api/login", "", cred, 200)
	token := p["token"].(string)
	second := f.call("/api/login", "", cred, 200)["token"].(string)
	f.call("/api/access-key/rotate", token, map[string]any{"id": "other", "confirm": true}, 403)
	next := f.call("/api/access-key/rotate", token, map[string]any{"confirm": true}, 200)["access_key"].(string)
	f.call("/api/sync", token, nil, 401)
	f.call("/api/sync", second, nil, 401)
	f.call("/api/access-key/rotate", token, map[string]any{"confirm": true}, 401)
	cred["access_key"] = next
	p = f.call("/api/login", "", cred, 200)
	if p["account_id"] != id {
		t.Fatal("identity lost")
	}
}

func TestBootstrapRotationInvalidatesEnrollmentAndOptionallyDevices(t *testing.T) {
	f := newAuthFixture(t)
	_, _, cred := f.account()
	p := f.call("/api/login", "", cred, 200)
	token := p["token"].(string)
	pair := f.call("/api/pair", token, map[string]any{}, 200)["code"].(string)
	old := f.call("/api/admin/bootstrap", "admin", nil, 200)["profile"].(string)
	applied := f.applied
	f.call("/api/admin/bootstrap/rotate", token, map[string]bool{"confirm": true}, 401)
	f.call("/api/admin/bootstrap/rotate", "admin", map[string]bool{}, 400)
	next := f.call("/api/admin/bootstrap/rotate", "admin", map[string]bool{"confirm": true}, 200)["profile"].(string)
	if next == old || f.applied != applied {
		t.Fatal("rotation did not change URI or restarted existing VPN")
	}
	f.call("/api/login", "", cred, 401)
	f.call("/api/register", "", map[string]string{"login": "bob"}, 401)
	f.call("/api/pair/claim", "", map[string]string{"code": pair, "name": "Phone", "platform": "android"}, 401)
	f.call("/api/sync", token, nil, 200)
	u, _ := url.Parse(next)
	f.key = u.Query().Get("access")
	f.call("/api/pair/claim", "", map[string]string{"code": pair, "name": "Phone", "platform": "android"}, 401)
	f.call("/api/login", "", cred, 200)
	// Startup migration must retain the rotated enrollment key.
	restarted, err := New(f.s.Store, f.s.Config, "admin-password-very-long", nil)
	if err != nil {
		t.Fatal(err)
	}
	got, err := restarted.bootstrapURI()
	if err != nil || got != next {
		t.Fatal("rotation lost after restart", err)
	}
	f.call("/api/admin/bootstrap/rotate", "admin", map[string]bool{"confirm": true, "revoke_devices": true}, 200)
	f.call("/api/sync", token, nil, 401)
	if f.applied == applied {
		t.Fatal("explicit revoke not applied")
	}
	// Profiles without the new enrollment key cannot create accounts.
	f.key = ""
	f.call("/api/register", "", map[string]string{"login": "carol"}, 401)
}
