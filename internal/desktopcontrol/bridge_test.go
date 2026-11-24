package desktopcontrol

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func makeBridge(t *testing.T) (*Bridge, *atomic.Int32) {
	t.Helper()
	calls := new(atomic.Int32)
	var b *Bridge
	key, err := loadSettingsKey(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	b = New("status-token", "private-token", key, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Header.Get("Authorization") != "Bearer "+b.controlToken {
			t.Error("missing internal authorization")
		}
		reply(w, 200, map[string]string{"access_key": "test-response-secret"})
	}), func(action string, raw json.RawMessage) (string, error) {
		return Description(action, raw, "https://vpn.example", nil)
	})
	return b, calls
}
func doRequest(h http.Handler, method, path, token, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}
func stage(t *testing.T, b *Bridge) map[string]string {
	t.Helper()
	w := doRequest(b.Public(http.NotFoundHandler()), "POST", "/local/control/request", "status-token", `{"action":"traffic-mode","data":{"mode":"all"}}`)
	if w.Code != 201 {
		t.Fatal(w.Code, w.Body.String())
	}
	var v map[string]string
	if json.Unmarshal(w.Body.Bytes(), &v) != nil {
		t.Fatal("bad ticket")
	}
	return v
}
func TestPublicTokenAndReceiptNeverAuthorizeMutation(t *testing.T) {
	b, calls := makeBridge(t)
	ticket := stage(t, b)
	for _, token := range []string{"", "status-token", ticket["id"], ticket["receipt"]} {
		w := doRequest(b.Privileged(), "POST", "/commit?id="+ticket["id"], token, `{}`)
		if w.Code != 401 {
			t.Fatal("unprivileged commit", w.Code)
		}
	}
	if calls.Load() != 0 {
		t.Fatal("staging performed a mutation")
	}
	if doRequest(b.Public(http.NotFoundHandler()), "GET", "/local/control/result/"+ticket["id"], "status-token", "").Code != 404 {
		t.Fatal("result exposed with read token")
	}
}
func TestApprovalBoundToRequestAndConsumedOnce(t *testing.T) {
	b, calls := makeBridge(t)
	ticket := stage(t, b)
	review := doRequest(b.Privileged(), "GET", "/review?id="+ticket["id"], "private-token", "")
	var info map[string]string
	json.Unmarshal(review.Body.Bytes(), &info)
	if !strings.Contains(info["summary"], "ВСЕМ") {
		t.Fatal("dialog did not disclose device-wide access")
	}
	if doRequest(b.Privileged(), "POST", "/commit?id="+ticket["id"], "private-token", `{"digest":"wrong"}`).Code != 409 {
		t.Fatal("changed request accepted")
	}
	body, _ := json.Marshal(map[string]string{"digest": info["digest"]})
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			doRequest(b.Privileged(), "POST", "/commit?id="+ticket["id"], "private-token", string(body))
		}()
	}
	wg.Wait()
	if calls.Load() != 1 {
		t.Fatal("replayed execution", calls.Load())
	}
	result := doRequest(b.Public(http.NotFoundHandler()), "GET", "/local/control/result/"+ticket["id"], ticket["receipt"], "")
	if result.Code != 200 || !strings.Contains(result.Body.String(), "test-response-secret") {
		t.Fatal("result unavailable")
	}
	if strings.Contains(review.Body.String(), "test-response-secret") {
		t.Fatal("response secret leaked to helper")
	}
}
func TestExpiryCancelAndCapacityAreFailClosed(t *testing.T) {
	b, calls := makeBridge(t)
	ticket := stage(t, b)
	review := doRequest(b.Privileged(), "GET", "/review?id="+ticket["id"], "private-token", "")
	var v map[string]string
	json.Unmarshal(review.Body.Bytes(), &v)
	body, _ := json.Marshal(map[string]string{"digest": v["digest"]})
	doRequest(b.Privileged(), "POST", "/cancel?id="+ticket["id"], "private-token", string(body))
	if doRequest(b.Privileged(), "POST", "/commit?id="+ticket["id"], "private-token", string(body)).Code != 409 {
		t.Fatal("cancelled request executed")
	}
	for i := 1; i < maxPending; i++ {
		stage(t, b)
	}
	if doRequest(b.Public(http.NotFoundHandler()), "POST", "/local/control/request", "status-token", `{"action":"vpn","data":{"enabled":false}}`).Code != 429 {
		t.Fatal("unbounded pending commands")
	}
	b.now = func() time.Time { return time.Now().Add(lifetime + time.Second) }
	if doRequest(b.Privileged(), "GET", "/review?id="+ticket["id"], "private-token", "").Code != 409 {
		t.Fatal("expired command survived")
	}
	if calls.Load() != 0 {
		t.Fatal("unauthorized mutation")
	}
}
func TestPinnedChannelRejectsImpostorAndRequiresNativeConsent(t *testing.T) {
	dir := t.TempDir()
	channel, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer channel.Listener.Close()
	b, calls := makeBridge(t)
	b.controlToken = channel.Credentials.Token
	server := &http.Server{Handler: b.Privileged()}
	go server.Serve(channel.Listener)
	defer server.Close()
	credentials, err := ReadCredentials(filepath.Join(dir, "control/session.json"))
	if err != nil {
		t.Fatal(err)
	}
	ticket := stage(t, b)
	if err = Approve(context.Background(), credentials, ticket["id"], func(string) bool { return false }); err == nil {
		t.Fatal("cancellation succeeded")
	}
	if calls.Load() != 0 {
		t.Fatal("cancel changed settings")
	}
	ticket = stage(t, b)
	if err = Approve(context.Background(), credentials, ticket["id"], func(string) bool { return true }); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 1 {
		t.Fatal("approved request not executed")
	}
	var stolen atomic.Int32
	impostor := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { stolen.Add(1) }))
	defer impostor.Close()
	credentials.Address = impostor.URL
	if err = Approve(context.Background(), credentials, stage(t, b)["id"], func(string) bool { t.Error("untrusted prompt"); return true }); err == nil {
		t.Fatal("impostor accepted")
	}
	if stolen.Load() != 0 {
		t.Fatal("secret sent to loopback impostor")
	}
}
func TestDescriptionDoesNotRevealKeysOrHideAction(t *testing.T) {
	for _, item := range []struct{ action, data string }{{"login", `{"access_key":"secret-value"}`}, {"bootstrap", `{"uri":"linevpn://1.2.3.4:8443?access=secret-value&pin=private-pin"}`}, {"pair/claim", `{"code":"secret-value"}`}} {
		s, err := Description(item.action, []byte(item.data), "https://vpn.example", nil)
		if err != nil || strings.Contains(s, "secret-value") || strings.Contains(s, "private-pin") {
			t.Fatal("dialog leaked credential", err)
		}
	}
	if _, err := Description("../vpn", []byte(`{}`), "", nil); err == nil {
		t.Fatal("unknown action accepted")
	}
}
func TestCredentialsRejectUntrustedDestinations(t *testing.T) {
	for _, addr := range []string{"http://127.0.0.1:1", "https://example.com:443", "https://user@127.0.0.1:443", "https://127.0.0.1:443/path"} {
		path := filepath.Join(t.TempDir(), "session.json")
		raw, _ := json.Marshal(Credentials{Address: addr, Token: strings.Repeat("x", 43), Pin: strings.Repeat("x", 43)})
		os.WriteFile(path, raw, 0600)
		if _, err := ReadCredentials(path); err == nil {
			t.Fatal("untrusted destination accepted", addr)
		}
	}
}
func TestOversizedProposalRejectedWithoutEffects(t *testing.T) {
	b, calls := makeBridge(t)
	r := httptest.NewRequest("POST", "/local/control/request", io.NopCloser(strings.NewReader(strings.Repeat("x", MaxBody+1))))
	r.Header.Set("Authorization", "Bearer status-token")
	w := httptest.NewRecorder()
	b.Public(http.NotFoundHandler()).ServeHTTP(w, r)
	if w.Code != 400 || calls.Load() != 0 {
		t.Fatal("oversized request accepted")
	}
}
