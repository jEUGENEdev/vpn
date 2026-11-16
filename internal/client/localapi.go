package client

import (
	"encoding/json"
	"errors"
	"github.com/jEUGENEdev/vpn/internal/secure"
	"github.com/jEUGENEdev/vpn/internal/server"
	"io"
	"net/http"
	"strings"
)

func (c *Client) Handler(token string, static http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
		if !strings.HasPrefix(r.URL.Path, "/local/") {
			static.ServeHTTP(w, r)
			return
		}
		if !secure.Equal(r.Header.Get("Authorization"), "Bearer "+token) {
			server.JSON(w, 401, map[string]string{"error": "unauthorized"})
			return
		}
		if r.URL.Path == "/local/state" && r.Method == "GET" {
			server.JSON(w, 200, c.State())
			return
		}
		if r.Method != "POST" {
			http.Error(w, "method not allowed", 405)
			return
		}
		raw, e := io.ReadAll(http.MaxBytesReader(w, r.Body, 32768))
		if e != nil {
			http.Error(w, "body too large", 413)
			return
		}
		var data map[string]any
		if e = json.Unmarshal(raw, &data); e != nil {
			http.Error(w, "invalid JSON", 400)
			return
		}
		action := strings.TrimPrefix(r.URL.Path, "/local/")
		var out any
		switch action {
		case "bootstrap":
			uri, _ := data["uri"].(string)
			e = c.SetBootstrap(uri)
			out = map[string]bool{"ok": e == nil}
		case "login", "register", "pair/claim":
			out, e = c.Auth(r.Context(), action, data)
		case "rules", "dismiss", "pair", "revoke":
			out, e = c.Action(r.Context(), action, data)
		default:
			e = errors.New("unknown action")
		}
		if e != nil {
			server.JSON(w, 400, map[string]string{"error": e.Error()})
			return
		}
		server.JSON(w, 200, out)
	})
}
