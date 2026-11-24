package server

import (
	"errors"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jEUGENEdev/vpn/internal/secure"
	"github.com/jEUGENEdev/vpn/internal/store"
)

func TestDeviceTokenCannotReplaceMasterKey(t *testing.T) {
	f := newAuthFixture(t)
	id, key, cred := f.account()
	token := f.call("/api/login", "", cred, 200)["token"].(string)
	f.call("/api/access-key/rotate", token, map[string]any{"confirm": true}, 403)
	f.s.Store.View(func(st store.State) error {
		if st.Accounts[id].KeyHash != secure.Hash(key) {
			t.Fatal("master key changed without knowledge of current key")
		}
		return nil
	})
	f.call("/api/sync", token, nil, 200)
}

func TestStorageFailureNeverLooksLikeAuthenticationFailureOrLeaksDetails(t *testing.T) {
	w := httptest.NewRecorder()
	fail(w, 401, fmt.Errorf("%w: /private/database/path", store.ErrStorage))
	if w.Code != 503 || strings.Contains(w.Body.String(), "/private") {
		t.Fatalf("unsafe storage response: %d %s", w.Code, w.Body.String())
	}
}

func TestRateLimitSharesIPv6PrefixAndHasHardBound(t *testing.T) {
	s := &Server{attempts: map[string]bucket{}}
	for i := 0; i < 12; i++ {
		r := httptest.NewRequest("POST", "/api/login", nil)
		r.RemoteAddr = fmt.Sprintf("[2606:4700:1:2::%x]:1234", i)
		got := s.limited(r, "login", 10, time.Minute)
		if got != (i >= 10) {
			t.Fatalf("IPv6 rotation bypassed limit on attempt %d", i+1)
		}
	}
	for i := 0; i < 10000; i++ {
		r := httptest.NewRequest("POST", "/api/login", nil)
		r.RemoteAddr = fmt.Sprintf("[2606:4700:%x::1]:1234", i)
		s.limited(r, "login", 10, time.Minute)
	}
	if len(s.attempts) > 8192 {
		t.Fatalf("unbounded rate limit table: %d", len(s.attempts))
	}
}

func TestCommittedKeySurvivesApplyFailureAndRetry(t *testing.T) {
	f := newAuthFixture(t)
	id, _, cred := f.account()
	token := f.call("/api/login", "", cred, 200)["token"].(string)
	calls := 0
	f.s.Apply = func(store.State) error { calls++; return errors.New("synthetic transport failure") }
	out := f.call("/api/admin/access-key", "admin", map[string]any{"id": id, "confirm": true}, 200)
	next, ok := out["access_key"].(string)
	if !ok || !validAccessKey(next) {
		t.Fatal("committed one-time key was lost")
	}
	f.call("/api/sync", token, nil, 401)
	f.s.Apply = func(st store.State) error {
		calls++
		if st.Accounts[id].KeyHash != secure.Hash(next) {
			t.Fatal("retry restored old credentials")
		}
		return nil
	}
	if err := f.s.Expire(time.Now()); err != nil {
		t.Fatal(err)
	}
	if calls != 2 {
		t.Fatalf("pending configuration was not retried: %d", calls)
	}
}

func TestInvalidGeneratedConfigurationDoesNotCommitOrStopTransport(t *testing.T) {
	f := newAuthFixture(t)
	id, key, cred := f.account()
	token := f.call("/api/login", "", cred, 200)["token"].(string)
	f.s.ValidateApply = func(store.State) error { return ErrInvalidConfiguration }
	f.s.Apply = func(store.State) error { t.Fatal("invalid candidate reached live transport"); return nil }
	err := f.s.mutation(func(st *store.State) error {
		a := st.Accounts[id]
		a.KeyHash = "invalid-candidate"
		st.Accounts[id] = a
		return nil
	})
	if !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatalf("unexpected error: %v", err)
	}
	f.s.Store.View(func(st store.State) error {
		if st.Accounts[id].KeyHash != secure.Hash(key) {
			t.Fatal("invalid candidate committed")
		}
		return nil
	})
	f.call("/api/sync", token, nil, 200)
}
