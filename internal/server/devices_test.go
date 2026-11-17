package server

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jEUGENEdev/vpn/internal/model"
	"github.com/jEUGENEdev/vpn/internal/secure"
	"github.com/jEUGENEdev/vpn/internal/store"
	"github.com/jEUGENEdev/vpn/internal/transport"
)

func deviceTestServer(t *testing.T) (*Server, func(string, string, any, int) map[string]any) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	s, err := New(st, Config{}, "admin-password-very-long", nil)
	if err != nil {
		t.Fatal(err)
	}

	if err := st.Update(func(v *store.State) error {
		for _, id := range []string{"a", "b"} {
			v.Accounts[id] = store.Account{Account: model.Account{ID: id, Login: id + "lice", Status: "active", Rules: []string{"private-user-choice.example"}, Revision: 1}, KeyHash: secure.Hash("lnv_" + strings.Repeat(id, 43))}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	call := func(path, token string, data any, status int) map[string]any {
		t.Helper()
		raw, _ := json.Marshal(data)
		method := "POST"
		if data == nil {
			method = "GET"
		}
		r := httptest.NewRequest(method, path, bytes.NewReader(raw))
		r.Header.Set("Authorization", "Bearer "+token)
		s.Store.View(func(st store.State) error { r.Header.Set("X-LineVPN-Profile", st.BootstrapKey); return nil })
		w := httptest.NewRecorder()
		s.Handler(nil).ServeHTTP(w, r)
		if w.Code != status {
			t.Fatalf("%s: got %d want %d: %s", path, w.Code, status, w.Body)
		}
		var out map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
		return out
	}
	return s, call
}

func TestDeviceSelectionAndCredentialRotation(t *testing.T) {
	s, call := deviceTestServer(t)
	old, err := s.enroll("a", "System laptop", "darwin")
	if err != nil {
		t.Fatal(err)
	}
	foreign, _ := s.enroll("b", "Other account laptop", "darwin")
	phone, _ := s.enroll("a", "Phone", "android")
	call("/api/app-vpn", old.Token, map[string]any{"enabled": true}, 200)
	var oldAppSecret string
	s.Store.View(func(st store.State) error { oldAppSecret = st.Devices[old.DeviceID].AppSecret; return nil })
	credentials := map[string]any{"access_key": "lnv_" + strings.Repeat("a", 43), "platform": "darwin"}
	wrong := map[string]any{"access_key": "wrong", "platform": "darwin"}
	call("/api/login", "", wrong, 401)
	selection := call("/api/login", "", credentials, 200)
	if selection["select_device"] != true || selection["token"] != nil {
		t.Fatal("selection must not issue credentials")
	}
	devices := selection["devices"].([]any)
	if len(devices) != 1 || devices[0].(map[string]any)["id"] != old.DeviceID {
		t.Fatal("selection leaked another account/platform")
	}
	for _, id := range []string{foreign.DeviceID, phone.DeviceID} {
		credentials["device_id"] = id
		call("/api/login", "", credentials, 503)
	}
	credentials["device_id"] = old.DeviceID
	updated := call("/api/login", "", credentials, 200)
	if updated["device_id"] != old.DeviceID || updated["token"] == old.Token || updated["uuid"] == old.UUID || updated["app_uuid"] == oldAppSecret {
		t.Fatal("existing device did not rotate all credentials")
	}
	call("/api/sync", old.Token, nil, 401)
	s.Store.View(func(st store.State) error {
		if len(st.Devices) != 3 || st.Devices[old.DeviceID].Name != "System laptop" {
			t.Fatal("reauth duplicated or renamed a selected device")
		}
		return nil
	})
	delete(credentials, "device_id")
	credentials["new_device"] = true
	added := call("/api/login", "", credentials, 200)
	s.Store.View(func(st store.State) error {
		if d := st.Devices[added["device_id"].(string)]; !strings.HasPrefix(d.Name, "Mac · ") {
			t.Fatal("fallback device has no generated name")
		}
		return nil
	})
}

func TestSameNameDevicesKeepIndependentAccess(t *testing.T) {
	s, call := deviceTestServer(t)
	credentials := map[string]any{"access_key": "lnv_" + strings.Repeat("a", 43), "platform": "android", "name": "Same phone model"}
	first := call("/api/login", "", credentials, 200)
	second := call("/api/login", "", credentials, 200)
	for _, key := range []string{"device_id", "token", "uuid"} {
		if first[key] == second[key] {
			t.Fatalf("two installations shared %s", key)
		}
	}
	for _, device := range []map[string]any{first, second} {
		call("/api/sync", device["token"].(string), nil, 200)
		call("/api/app-vpn", device["token"].(string), map[string]any{"enabled": true}, 200)
	}
	s.Store.View(func(st store.State) error {
		if len(st.Devices) != 2 {
			t.Fatal("device records were overwritten")
		}
		return nil
	})
	call("/api/revoke", first["token"].(string), map[string]any{"id": second["device_id"]}, 200)
	call("/api/sync", first["token"].(string), nil, 200)
	call("/api/sync", second["token"].(string), nil, 401)
}

func TestPairSelectionIsAtomicAndCodeSurvivesChoice(t *testing.T) {
	s, call := deviceTestServer(t)
	issuer, _ := s.enroll("a", "Phone", "android")
	laptop, _ := s.enroll("a", "Laptop", "darwin")
	code := call("/api/pair", issuer.Token, map[string]any{}, 200)["code"].(string)
	input := map[string]any{"code": code, "platform": "darwin"}
	choice := call("/api/pair/claim", "", input, 200)
	if choice["select_device"] != true {
		t.Fatal(choice)
	}
	s.Store.View(func(st store.State) error {
		if len(st.Pairs) != 1 {
			t.Fatal("selection consumed code")
		}
		return nil
	})
	input["device_id"] = laptop.DeviceID
	result := call("/api/pair/claim", "", input, 200)
	if result["device_id"] != laptop.DeviceID {
		t.Fatal("pairing duplicated device")
	}
	call("/api/pair/claim", "", input, 401)
	call("/api/sync", laptop.Token, nil, 401)
	// No devices of a platform still offers the explicit add-current path.
	code = call("/api/pair", issuer.Token, map[string]any{}, 200)["code"].(string)
	choice = call("/api/pair/claim", "", map[string]any{"code": code, "platform": "windows"}, 200)
	if len(choice["devices"].([]any)) != 0 {
		t.Fatal(choice)
	}
	call("/api/pair/claim", "", map[string]any{"code": code, "platform": "windows", "new_device": true}, 200)
}

func TestDeleteDeviceRemovesAccessReferencesAndAdminPolicy(t *testing.T) {
	s, call := deviceTestServer(t)
	first, _ := s.enroll("a", "Laptop", "darwin")
	second, _ := s.enroll("a", "Phone", "android")
	foreign, _ := s.enroll("b", "Foreign", "darwin")
	call("/api/app-vpn", first.Token, map[string]any{"enabled": true}, 200)
	call("/api/discover", first.Token, map[string]any{"failed_targets": []string{"example.net"}}, 200)
	code := call("/api/pair", first.Token, map[string]any{}, 200)["code"].(string)
	call("/api/revoke", foreign.Token, map[string]any{"id": first.DeviceID}, 403)
	admin := call("/api/admin/login", "", map[string]any{"password": "admin-password-very-long"}, 200)["token"].(string)
	list := call("/api/admin/accounts", admin, nil, 200)
	raw, _ := json.Marshal(list)
	for _, forbidden := range []string{"private-user-choice.example", `"rules"`, `"revision"`, `"password_hash"`, `"token_hash"`, `"vless"`} {
		if bytes.Contains(raw, []byte(forbidden)) {
			t.Fatalf("admin response exposes %s", forbidden)
		}
	}
	// Confirm both VLESS credentials disappear from the applied runtime config.
	var removed store.Device
	s.Store.View(func(st store.State) error { removed = st.Devices[first.DeviceID]; return nil })
	applied := 0
	s.Apply = func(st store.State) error {
		applied++
		config, _ := json.Marshal(transport.ServerConfig(st, transport.ServerOptions{}, time.Now()))
		if bytes.Contains(config, []byte(removed.Secret)) || bytes.Contains(config, []byte(removed.AppSecret)) {
			t.Fatal("deleted credentials remain in transport")
		}
		return nil
	}
	call("/api/revoke", first.Token, map[string]any{"id": first.DeviceID}, 200)
	if applied != 1 {
		t.Fatal("runtime not reconfigured on self deletion")
	}
	for _, path := range []string{"/api/sync", "/api/discover", "/api/rules", "/api/app-vpn", "/api/dismiss", "/api/pair", "/api/revoke"} {
		var body any = map[string]any{}
		if path == "/api/sync" {
			body = nil
		}
		call(path, first.Token, body, 401)
	}
	call("/api/pair/claim", "", map[string]any{"code": code, "name": "Unknown", "platform": "darwin"}, 401)
	s.Store.View(func(st store.State) error {
		if _, exists := st.Devices[first.DeviceID]; exists {
			t.Fatal("deleted record still stored")
		}
		if stillAuthorized(&st, removed) {
			t.Fatal("in-flight request can reuse deleted authorization")
		}
		for _, q := range st.Requests {
			if _, exists := q.FailedDevices[first.DeviceID]; exists {
				t.Fatal("orphaned device reference")
			}
		}
		if len(st.Pairs) != 0 || len(st.Accounts["a"].Rules) != 1 {
			t.Fatal("deletion lost shared policy or retained codes")
		}
		return nil
	})
	for _, device := range call("/api/sync", second.Token, nil, 200)["devices"].([]any) {
		if device.(map[string]any)["id"] == first.DeviceID {
			t.Fatal("deleted device still visible")
		}
	}
	call("/api/admin/revoke", admin, map[string]any{"id": second.DeviceID}, 200)
	call("/api/sync", second.Token, nil, 401)
}

func TestDeletePersistsWhenTransportApplyFails(t *testing.T) {
	s, call := deviceTestServer(t)
	device, _ := s.enroll("a", "Laptop", "darwin")
	s.Apply = func(store.State) error { return errors.New("runtime unavailable") }
	call("/api/revoke", device.Token, map[string]any{"id": device.DeviceID}, 503)
	call("/api/sync", device.Token, nil, 401)
	s.Store.View(func(st store.State) error {
		if len(st.Devices) != 0 {
			t.Fatal("failed apply restored deleted credentials")
		}
		return nil
	})
}

func TestDeleteLegacyPairCodes(t *testing.T) {
	st := store.Empty()
	d := store.Device{Device: model.Device{ID: "deleted", AccountID: "a"}}
	st.Pairs[secure.Hash("legacy")] = store.Pair{AccountID: "a"}
	st.Pairs[secure.Hash("other-device")] = store.Pair{AccountID: "a", DeviceID: "remaining"}
	st.Pairs[secure.Hash("other-account")] = store.Pair{AccountID: "b"}
	deleteDevice(&st, d)
	if len(st.Pairs) != 2 {
		t.Fatal("legacy/other issuer pair deletion wrong")
	}
}

func TestExpiredDeviceReauthenticatesWithoutDuplicate(t *testing.T) {
	s, _ := deviceTestServer(t)
	old, err := s.enroll("a", "Expired Mac", "darwin")
	if err != nil {
		t.Fatal(err)
	}
	s.Store.Update(func(st *store.State) error {
		d := st.Devices[old.DeviceID]
		d.Expires = time.Now().Add(-time.Minute)
		st.Devices[d.ID] = d
		return nil
	})
	if err := s.Expire(time.Now()); err != nil {
		t.Fatal(err)
	}
	out, err := s.enrollChoice("a", deviceChoice{Platform: "darwin", DeviceID: old.DeviceID}, "")
	if err != nil {
		t.Fatal(err)
	}
	profile := out.(model.Profile)
	if profile.DeviceID != old.DeviceID || profile.Token == old.Token {
		t.Fatal("expiry duplicated device or retained keys")
	}
	s.Store.View(func(st store.State) error {
		if len(st.Devices) != 1 || st.Devices[old.DeviceID].Revoked {
			t.Fatal("expired device not renewed")
		}
		return nil
	})
}

func TestSameAccountDevicesKeepIndependentSessions(t *testing.T) {
	_, call := deviceTestServer(t)
	credentials := map[string]any{"access_key": "lnv_" + strings.Repeat("a", 43), "name": "Same model", "platform": "android"}
	first := call("/api/login", "", credentials, 200)
	second := call("/api/login", "", credentials, 200)
	for _, field := range []string{"device_id", "token", "uuid"} {
		if first[field] == second[field] {
			t.Fatalf("devices shared %s", field)
		}
	}
	for _, profile := range []map[string]any{first, second} {
		state := call("/api/sync", profile["token"].(string), nil, 200)
		if len(state["devices"].([]any)) != 2 {
			t.Fatal("one device replaced the other")
		}
	}
	call("/api/app-vpn", first["token"].(string), map[string]any{"enabled": true}, 200)
	credentials["device_id"] = first["device_id"]
	replacement := call("/api/login", "", credentials, 200)
	call("/api/sync", first["token"].(string), nil, 401)
	call("/api/sync", replacement["token"].(string), nil, 200)
	call("/api/sync", second["token"].(string), nil, 200)
	call("/api/revoke", replacement["token"].(string), map[string]any{"id": first["device_id"]}, 200)
	call("/api/sync", second["token"].(string), nil, 200)
}
