package desktopcontrol

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestSettingsGrantScopeAndServiceRestart(t *testing.T) {
	b, calls := makeBridge(t)
	now := time.Now().Truncate(time.Second)
	b.now = func() time.Time { return now }
	dir := t.TempDir()
	first, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	first.Listener.Close()
	b.settingsKey = first.SettingsKey
	h := b.Public(http.NotFoundHandler())
	req := doRequest(h, "POST", "/local/control/request", "status-token", `{"action":"settings-session","data":{}}`)
	var ticket map[string]string
	if req.Code != 201 || json.Unmarshal(req.Body.Bytes(), &ticket) != nil {
		t.Fatal("session not staged")
	}
	path := settingsPrefix + "traffic-mode"
	for _, token := range []string{"status-token", "private-token", ticket["id"], ticket["receipt"]} {
		if doRequest(h, "POST", path, token, "{}").Code != 401 {
			t.Fatal("unapproved settings request")
		}
	}
	var review map[string]string
	r := doRequest(b.Privileged(), "GET", "/review?id="+ticket["id"], "private-token", "")
	if json.Unmarshal(r.Body.Bytes(), &review) != nil || !strings.Contains(review["summary"], "12 часов") {
		t.Fatal("scope missing from approval")
	}
	body, _ := json.Marshal(map[string]string{"digest": review["digest"]})
	r = doRequest(b.Privileged(), "POST", "/commit?id="+ticket["id"], "private-token", string(body))
	if r.Code != 200 || strings.Contains(r.Body.String(), "token") {
		t.Fatal("grant leaked to helper")
	}
	if doRequest(h, "GET", "/local/control/result/"+ticket["id"], "status-token", "").Code != 404 {
		t.Fatal("grant leaked to status reader")
	}
	r = doRequest(h, "GET", "/local/control/result/"+ticket["id"], ticket["receipt"], "")
	var result struct {
		Body struct {
			Token   string
			Expires int64 `json:"expires_at"`
		}
	}
	if json.Unmarshal(r.Body.Bytes(), &result) != nil || result.Body.Expires != now.Add(settingsLifetime).Unix() {
		t.Fatal("no approved grant")
	}
	token := result.Body.Token
	for _, action := range []string{"applications", "rules", "dismiss", "vpn", "traffic-mode", "applications/add"} {
		if doRequest(h, "POST", settingsPrefix+action, token, "{}").Code != 200 {
			t.Fatal("grant rejected", action)
		}
	}
	for _, action := range []string{"bootstrap", "login", "register", "pair/claim", "access-key/rotate", "pair", "revoke", "settings-session", "../vpn"} {
		if doRequest(h, "POST", settingsPrefix+action, token, "{}").Code != 403 {
			t.Fatal("grant authorized account or unknown command", action)
		}
	}
	if doRequest(h, "GET", path, token, "").Code != 405 || calls.Load() != 6 {
		t.Fatal("unexpected delegated execution")
	}
	second, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Listener.Close()
	b.settingsKey = second.SettingsKey
	if doRequest(h, "POST", path, token, "{}").Code != 200 {
		t.Fatal("network restart lost settings session")
	}
	modified := []byte(token)
	if modified[0] == 'A' {
		modified[0] = 'B'
	} else {
		modified[0] = 'A'
	}
	if doRequest(h, "POST", path, string(modified), "{}").Code != 401 {
		t.Fatal("invalid grant accepted")
	}
	now = now.Add(settingsLifetime)
	if doRequest(h, "POST", path, token, "{}").Code != 401 {
		t.Fatal("expired grant accepted")
	}
	now = now.Add(-settingsLifetime)
	b.settingsKey, err = loadSettingsKey(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if doRequest(h, "POST", path, token, "{}").Code != 401 || calls.Load() != 7 {
		t.Fatal("grant accepted after reinstall")
	}
}
