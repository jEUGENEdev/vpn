package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jEUGENEdev/vpn/internal/ui"
)

func enablePublicAdmin(t *testing.T, s *Server) {
	t.Helper()
	if err := json.Unmarshal([]byte(`{"public_admin":true}`), &s.Config); err != nil {
		t.Fatal(err)
	}
}

func TestPublicAdminLoginAndAuthorization(t *testing.T) {
	f := newAuthFixture(t)
	enablePublicAdmin(t, f.s)
	h := f.s.Handler(nil)
	call := func(method, path, token, body string, want int) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequest(method, "https://8.8.8.8:8443"+path, strings.NewReader(body))
		r.RemoteAddr = "9.9.9.9:1234"
		r.Header.Set("Origin", "https://8.8.8.8:8443")
		if token != "" {
			r.Header.Set("Authorization", "Bearer "+token)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != want {
			t.Fatalf("%s %s: %d, want %d: %s", method, path, w.Code, want, w.Body.String())
		}
		if w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("X-Frame-Options") != "DENY" {
			t.Fatal("missing response protections")
		}
		return w
	}
	call("GET", "/healthz", "", "", 200)
	call("POST", "/api/admin/login", "", `{"password":"wrong"}`, 401)
	for _, route := range []struct{ method, path string }{
		{"GET", "/api/admin/accounts"}, {"GET", "/api/admin/bootstrap"},
		{"POST", "/api/admin/bootstrap/rotate"}, {"POST", "/api/admin/account"},
		{"POST", "/api/admin/revoke"}, {"POST", "/api/admin/access-key"},
		{"POST", "/api/admin/logout"},
	} {
		call(route.method, route.path, "", `{}`, 401)
	}
	w := call("POST", "/api/admin/login", "", `{"password":"admin-password-very-long"}`, 200)
	var login struct{ Token string }
	if err := json.Unmarshal(w.Body.Bytes(), &login); err != nil || login.Token == "" {
		t.Fatal("missing admin session", err)
	}
	call("GET", "/api/admin/accounts", login.Token, "", 200)
	call("GET", "/api/admin/bootstrap", login.Token, "", 200)
	_, _, credentials := f.account()
	device := f.call("/api/login", "", credentials, 200)["token"].(string)
	call("GET", "/api/admin/accounts", device, "", 401)
	call("GET", "/api/sync", device, "", 200)
	call("POST", "/api/admin/logout", login.Token, `{}`, 200)
	call("GET", "/api/admin/accounts", login.Token, "", 401)
}

func TestPublicAdminRejectsCrossOriginAndLimitsLogin(t *testing.T) {
	f := newAuthFixture(t)
	enablePublicAdmin(t, f.s)
	h := f.s.Handler(nil)
	r := httptest.NewRequest("POST", "https://8.8.8.8:8443/api/admin/login", strings.NewReader(`{"password":"admin-password-very-long"}`))
	r.Header.Set("Origin", "https://attacker.invalid")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatalf("cross-origin login: %d", w.Code)
	}
	for i := 0; i < 9; i++ {
		r := httptest.NewRequest("POST", "https://8.8.8.8:8443/api/admin/login", strings.NewReader(`{"password":"wrong"}`))
		r.RemoteAddr = "9.9.9.9:1234"
		r.Header.Set("X-Forwarded-For", fmt.Sprintf("8.8.8.%d", i))
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		want := http.StatusUnauthorized
		if i == 8 {
			want = http.StatusTooManyRequests
		}
		if w.Code != want {
			t.Fatalf("attempt %d: %d, want %d", i, w.Code, want)
		}
	}
}

func TestPublicAdminStaticFilesRequireExplicitConfiguration(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		f := newAuthFixture(t)
		f.s.Config.PublicAdmin = enabled
		h := f.s.Handler(ui.Handler("admin"))
		for _, path := range []string{"/", "/app.js", "/style.css"} {
			r := httptest.NewRequest("GET", "https://8.8.8.8:8443"+path, nil)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			want := http.StatusNotFound
			if enabled {
				want = http.StatusOK
			}
			if w.Code != want {
				t.Fatalf("public_admin=%t %s: %d, want %d", enabled, path, w.Code, want)
			}
			if enabled && path == "/" && !strings.Contains(w.Body.String(), `id="login-form"`) {
				t.Fatal("public root did not serve the login page")
			}
		}
	}
}

func TestPublicAdminLimitsIPv6PrefixesAndDistributedAttempts(t *testing.T) {
	for _, ipv6 := range []bool{false, true} {
		f := newAuthFixture(t)
		enablePublicAdmin(t, f.s)
		h := f.s.Handler(nil)
		limit := 30
		if ipv6 {
			limit = 8
		}
		for i := 0; i <= limit; i++ {
			r := httptest.NewRequest("POST", "https://8.8.8.8:8443/api/admin/login", strings.NewReader(`{"password":"wrong"}`))
			r.RemoteAddr = fmt.Sprintf("9.9.9.%d:1234", i+1)
			if ipv6 {
				r.RemoteAddr = fmt.Sprintf("[2606:4700:4700::%x]:1234", i+1)
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			want := http.StatusUnauthorized
			if i == limit {
				want = http.StatusTooManyRequests
			}
			if w.Code != want {
				t.Fatalf("ipv6=%t attempt %d: %d, want %d", ipv6, i, w.Code, want)
			}
		}
	}
}
