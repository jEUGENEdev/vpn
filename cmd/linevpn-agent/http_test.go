package main

import (
	"github.com/jEUGENEdev/vpn/internal/client"
	"github.com/jEUGENEdev/vpn/internal/transport"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDesktopReadTokenCannotChangePolicy(t *testing.T) {
	c, err := client.New(t.TempDir(), &transport.Dialer{})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	h := desktopHandler(c, "public-status-token", http.NotFoundHandler())
	r := httptest.NewRequest("POST", "http://localhost/local/traffic-mode", strings.NewReader(`{"mode":"all"}`))
	r.Header.Set("Authorization", "Bearer public-status-token")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Errorf("ordinary local process changed policy: HTTP %d", w.Code)
	}
	if c.State().(map[string]any)["traffic_mode"] != "selective" {
		t.Fatal("read token granted device-wide VPN")
	}
}
