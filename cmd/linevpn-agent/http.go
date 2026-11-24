package main

import (
	"github.com/jEUGENEdev/vpn/internal/client"
	"net/http"
	"strings"
)

func desktopHandler(c *client.Client, token string, static http.Handler) http.Handler {
	handler := c.Handler(token, static)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/local/") && (r.Method != "GET" || r.URL.Path != "/local/state") {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte(`{"error":"Для изменения настроек откройте приложение «Сеть»"}`))
			return
		}
		handler.ServeHTTP(w, r)
	})
}
