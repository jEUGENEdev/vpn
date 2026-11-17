package server

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/jEUGENEdev/vpn/internal/model"
	"github.com/jEUGENEdev/vpn/internal/store"
)

func TestApplicationRulesAreAccountAndPlatformScoped(t *testing.T) {
	s, call := deviceTestServer(t)
	phone, err := s.enroll("a", "Phone", "android")
	if err != nil {
		t.Fatal(err)
	}
	other, _ := s.enroll("b", "Other account", "android")
	mac, _ := s.enroll("a", "Mac", "darwin")
	id := strings.Repeat("a", 64)
	changes := map[string]any{"changes": []model.ApplicationRuleChange{{ID: id, Decision: "trusted"}}}
	call("/api/application-rules", "", changes, 401)
	applies := 0
	s.Apply = func(store.State) error { applies++; return nil }
	saved := call("/api/application-rules", phone.Token, changes, 200)
	if applies != 0 {
		t.Fatal("metadata backup reconfigured live transports")
	}
	if len(saved["application_rules"].([]any)) != 1 {
		t.Fatal("rule missing")
	}
	// Replaying a response-lost write is idempotent.
	again := call("/api/application-rules", phone.Token, changes, 200)
	if again["revision"] != saved["revision"] {
		t.Fatal("retry changed revision")
	}
	for _, token := range []string{other.Token, mac.Token} {
		profile := call("/api/sync", token, nil, 200)["profile"].(map[string]any)
		if len(profile["application_rules"].([]any)) != 0 {
			t.Fatal("policy crossed account or platform")
		}
	}
	// Fresh authentication gets the rules even with a newly generated device ID.
	fresh := call("/api/login", "", map[string]any{"access_key": "lnv_" + strings.Repeat("a", 43), "name": "Reinstalled phone", "platform": "android"}, 200)
	if len(fresh["application_rules"].([]any)) != 1 || fresh["device_id"] == phone.DeviceID {
		t.Fatal("clean install failed to recover policy")
	}
	// Unknown fields cannot inject a platform, user name, path or account scope.
	for _, invalid := range []any{
		map[string]any{"changes": []map[string]string{{"id": id, "decision": "trusted", "platform": "darwin"}}},
		map[string]any{"changes": []model.ApplicationRuleChange{{ID: "forged", Decision: "trusted"}}},
		map[string]any{"changes": []model.ApplicationRuleChange{{ID: id, Decision: "pending"}}},
		map[string]any{"changes": []model.ApplicationRuleChange{}},
		map[string]any{"changes": make([]model.ApplicationRuleChange, 65)},
	} {
		call("/api/application-rules", phone.Token, invalid, 400)
	}
	admin := call("/api/admin/login", "", map[string]string{"password": "admin-password-very-long"}, 200)["token"].(string)
	raw, _ := json.Marshal(call("/api/admin/accounts", admin, nil, 200))
	if strings.Contains(string(raw), "application_rules") || strings.Contains(string(raw), id) {
		t.Fatal("admin API exposed user choices")
	}
	call("/api/revoke", fresh["token"].(string), map[string]string{"id": phone.DeviceID}, 200)
	call("/api/application-rules", phone.Token, changes, 401)
	profile := call("/api/sync", fresh["token"].(string), nil, 200)["profile"].(map[string]any)
	if len(profile["application_rules"].([]any)) != 1 {
		t.Fatal("revocation deleted account rules")
	}
}

func TestApplicationRuleLimitIsAtomicAndExistingChoicesRemainEditable(t *testing.T) {
	s, call := deviceTestServer(t)
	phone, err := s.enroll("a", "Phone", "android")
	if err != nil {
		t.Fatal(err)
	}
	if err = s.Store.Update(func(st *store.State) error {
		a := st.Accounts["a"]
		a.ApplicationRules = map[string]model.ApplicationRule{}
		for i := 0; i < 512; i++ {
			id := fmt.Sprintf("%064x", i)
			a.ApplicationRules["android:"+id] = model.ApplicationRule{ID: id, Platform: "android", Decision: "trusted"}
		}
		st.Accounts["a"] = a
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	old, newID := fmt.Sprintf("%064x", 0), fmt.Sprintf("%064x", 512)
	call("/api/application-rules", phone.Token, map[string]any{"changes": []model.ApplicationRuleChange{{ID: old, Decision: "addresses"}, {ID: newID, Decision: "trusted"}}}, 409)
	if err = s.Store.View(func(st store.State) error {
		if st.Accounts["a"].ApplicationRules["android:"+old].Decision != "trusted" {
			t.Fatal("failed batch partially committed")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	call("/api/application-rules", phone.Token, map[string]any{"changes": []model.ApplicationRuleChange{{ID: old, Decision: "addresses"}}}, 200)
	// A legacy installation cannot revive an explicitly revoked app trust.
	profile := call("/api/application-rules", phone.Token, map[string]any{"changes": []model.ApplicationRuleChange{{ID: old, Decision: "trusted", OnlyIfAbsent: true}}}, 200)
	if profile["application_rules"].([]any)[0].(map[string]any)["decision"] != "addresses" {
		t.Fatal("legacy migration widened trust")
	}
}
