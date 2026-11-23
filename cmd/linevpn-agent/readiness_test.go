package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"github.com/jEUGENEdev/vpn/internal/desktopcontrol"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestInstallerReadiness(t *testing.T) {
	dir := t.TempDir()
	token := strings.Repeat("a", 43)
	if err := os.WriteFile(filepath.Join(dir, "ui-token"), []byte(token), 0600); err != nil {
		t.Fatal(err)
	}
	status, body, calls := 200, `{"vpn_enabled":false}`, 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Method != "GET" || r.URL.Path != "/local/state" || r.Header.Get("Authorization") != "Bearer "+token {
			t.Error("unexpected request")
		}
		w.WriteHeader(status)
		w.Write([]byte(body))
	}))
	defer server.Close()
	if checkService(context.Background(), dir, server.URL) == nil {
		t.Fatal("missing session accepted")
	}
	session, _ := json.Marshal(map[string]string{"certificate": base64.StdEncoding.EncodeToString(server.Certificate().Raw)})
	if err := os.WriteFile(filepath.Join(dir, "ui-session.json"), session, 0600); err != nil {
		t.Fatal(err)
	}
	if err := checkService(context.Background(), dir, server.URL); err != nil {
		t.Fatal(err)
	}
	for _, invalid := range []string{`{}`, `{"vpn_enabled":"yes"}`, `broken`} {
		body = invalid
		if checkService(context.Background(), dir, server.URL) == nil {
			t.Fatal("invalid status accepted")
		}
	}
	status, body = 401, `{"vpn_enabled":false}`
	if checkService(context.Background(), dir, server.URL) == nil {
		t.Fatal("unauthenticated service accepted")
	}
	status = 302
	if checkService(context.Background(), dir, server.URL) == nil {
		t.Fatal("redirect accepted")
	}
	server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if waitForService(ctx, dir, server.URL) == nil {
		t.Fatal("stopped service accepted")
	}
	if calls != 6 {
		t.Fatalf("unexpected request count: %d", calls)
	}
	got, _ := os.ReadFile(filepath.Join(dir, "ui-token"))
	if string(got) != token {
		t.Fatal("readiness changed existing identity")
	}
}

func TestReadinessUsesActualServiceCertificate(t *testing.T) {
	dir := t.TempDir()
	channel, err := desktopcontrol.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer channel.Listener.Close()
	token := strings.Repeat("b", 43)
	session, _ := json.Marshal(map[string]string{"certificate": channel.Credentials.Certificate})
	if err = os.WriteFile(filepath.Join(dir, "ui-session.json"), session, 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(dir, "ui-token"), []byte(token), 0600); err != nil {
		t.Fatal(err)
	}
	var requests atomic.Int32
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.Header.Get("Authorization") != "Bearer "+token {
			t.Error("wrong token")
		}
		w.Write([]byte(`{"vpn_enabled":true}`))
	})}
	defer server.Close()
	go server.Serve(channel.Listener)
	if err = checkService(context.Background(), dir, channel.Credentials.Address); err != nil {
		t.Fatal(err)
	}
	impostor, err := desktopcontrol.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer impostor.Listener.Close()
	fake := &http.Server{Handler: server.Handler}
	defer fake.Close()
	go fake.Serve(impostor.Listener)
	if checkService(context.Background(), dir, impostor.Credentials.Address) == nil {
		t.Fatal("untrusted service accepted")
	}
	if requests.Load() != 1 {
		t.Fatal("status token reached impostor")
	}
}
