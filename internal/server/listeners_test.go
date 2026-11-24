package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestPublicListenerNeverServesAdministration(t *testing.T) {
	f := newAuthFixture(t)
	admins, attempts := len(f.s.admins), len(f.s.attempts)
	for _, path := range []string{"/api/admin/login", "/api/admin/accounts", "/api/admin/bootstrap", "/api/admin/bootstrap/rotate", "/api/admin/account", "/api/admin/revoke", "/api/admin/logout", "/api/admin/access-key"} {
		for _, method := range []string{"GET", "POST"} {
			r := httptest.NewRequest(method, path, strings.NewReader(`{"password":"admin-password-very-long"}`))
			r.RemoteAddr = "127.0.0.1:1234"
			r.Host = "localhost:8444"
			r.Header.Set("X-Forwarded-For", "127.0.0.1")
			w := httptest.NewRecorder()
			f.s.Handler(nil).ServeHTTP(w, r)
			if w.Code != http.StatusNotFound {
				t.Fatalf("public %s %s: got %d", method, path, w.Code)
			}
		}
	}
	if len(f.s.admins) != admins || len(f.s.attempts) != attempts {
		t.Fatal("public listener reached admin authentication")
	}
}

// Test-only composition lets lifecycle tests use both isolated listeners.
func testServerHandler(s *Server) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/admin/") {
			s.AdminHandler(nil).ServeHTTP(w, r)
		} else {
			s.Handler(nil).ServeHTTP(w, r)
		}
	})
}

func TestAdminListenAddressMustBeLoopback(t *testing.T) {
	c := Config{PublicIP: "8.8.8.8"}
	c.Transport.Port = 443
	c.Transport.Path = "/test"
	for _, address := range []string{"", "127.0.0.1:8444", "[::1]:8444"} {
		c.AdminAddress = address
		if err := c.Validate(); err != nil {
			t.Fatal(address, err)
		}
	}
	for _, address := range []string{":8444", "0.0.0.0:8444", "[::]:8444", "8.8.8.8:8444", "localhost:8444", "127.0.0.1:0"} {
		c.AdminAddress = address
		if c.Validate() == nil {
			t.Fatal("accepted public/ambiguous admin address", address)
		}
	}
}

func TestAdminLoginRateLimitAndCrossOrigin(t *testing.T) {
	f := newAuthFixture(t)
	h := f.s.AdminHandler(nil)
	for i := 0; i < 9; i++ {
		r := httptest.NewRequest("POST", "/api/admin/login", strings.NewReader(`{"password":"wrong"}`))
		r.RemoteAddr = "127.0.0.1:4321"
		r.Header.Set("X-Forwarded-For", "8.8.8.8")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		want := 401
		if i == 8 {
			want = 429
		}
		if w.Code != want {
			t.Fatal(i, w.Code)
		}
	}
	r := httptest.NewRequest("POST", "/api/admin/login", strings.NewReader(`{"password":"admin-password-very-long"}`))
	r.Header.Set("Origin", "https://attacker.invalid")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatalf("cross-origin login accepted: %d", w.Code)
	}
}
