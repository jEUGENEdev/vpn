package desktopcontrol

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestOperatorTicketRequiresNativeConsent(t *testing.T) {
	b, calls := makeBridge(t)
	ticket := stage(t, b)
	body, _ := json.Marshal(ticket)
	prompts, allow := 0, false
	h := b.Operator("operator-only", func(_ context.Context, summary string) (bool, error) {
		prompts++
		if !strings.Contains(summary, "ВСЕМ приложениям") {
			t.Fatal("dialog did not describe the staged change")
		}
		return allow, nil
	})
	const path = "/local/control/confirm"
	for _, token := range []string{"status-token", "private-token", ticket["receipt"], ""} {
		if doRequest(h, "POST", path, token, string(body)).Code != 403 {
			t.Fatal("unauthorized prompt")
		}
	}
	if doRequest(h, "POST", path, "operator-only", `{"receipt":"unknown"}`).Code != 409 || prompts != 0 {
		t.Fatal("unbound prompt")
	}
	if doRequest(h, "POST", path, "operator-only", string(body)).Code != 200 || calls.Load() != 0 || prompts != 1 {
		t.Fatal("cancelled change executed")
	}
	allow = true
	if doRequest(h, "POST", path, "operator-only", string(body)).Code != 409 || prompts != 1 {
		t.Fatal("cancelled ticket reused")
	}
	ticket = stage(t, b)
	body, _ = json.Marshal(ticket)
	w := doRequest(h, "POST", path, "operator-only", string(body))
	if w.Code != 200 || strings.Contains(w.Body.String(), "test-response-secret") || calls.Load() != 1 || prompts != 2 {
		t.Fatal("approved command or result isolation failed")
	}
	if get := doRequest(b.Public(http.NotFoundHandler()), "GET", "/local/control/result/"+ticket["id"], ticket["receipt"], ""); !strings.Contains(get.Body.String(), "test-response-secret") {
		t.Fatal("missing result for requester")
	}
}

func TestOperatorPromptBusyExpiryAndFailure(t *testing.T) {
	b, calls := makeBridge(t)
	now := time.Now()
	b.now = func() time.Time { return now }
	first, _ := json.Marshal(stage(t, b))
	second, _ := json.Marshal(stage(t, b))
	entered, release := make(chan struct{}), make(chan struct{})
	h := b.Operator("operator", func(context.Context, string) (bool, error) {
		close(entered)
		<-release
		return true, nil
	})
	result := make(chan *httptest.ResponseRecorder, 1)
	go func() { result <- doRequest(h, "POST", "/local/control/confirm", "operator", string(first)) }()
	<-entered
	if doRequest(h, "POST", "/local/control/confirm", "operator", string(second)).Code != 409 {
		t.Fatal("concurrent OS dialog")
	}
	now = now.Add(lifetime)
	close(release)
	if (<-result).Code != 409 || calls.Load() != 0 {
		t.Fatal("expired ticket executed")
	}
	h = b.Operator("operator", func(context.Context, string) (bool, error) { return false, errors.New("no user session") })
	body, _ := json.Marshal(stage(t, b))
	if doRequest(h, "POST", "/local/control/confirm", "operator", string(body)).Code != 503 || calls.Load() != 0 {
		t.Fatal("unavailable dialog allowed a change")
	}
}
