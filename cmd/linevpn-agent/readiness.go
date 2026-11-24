package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Installation succeeds only after the installed service answers over its
// authenticated local channel. Never recover networking or change saved state.
func waitForService(ctx context.Context, dir, address string) error {
	var last error
	for {
		last = checkService(ctx, dir, address)
		if last == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return last
		case <-time.After(250 * time.Millisecond):
		}
	}
}

func checkService(ctx context.Context, dir, address string) error {
	raw, err := os.ReadFile(filepath.Join(dir, "ui-session.json"))
	var session struct {
		Certificate string `json:"certificate"`
	}
	if err != nil || len(raw) > 8192 || json.Unmarshal(raw, &session) != nil {
		return errors.New("service readiness: public session is unavailable")
	}
	der, err := base64.StdEncoding.DecodeString(session.Certificate)
	if err != nil {
		return errors.New("service readiness: invalid public certificate")
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		return errors.New("service readiness: invalid public certificate")
	}
	token, err := os.ReadFile(filepath.Join(dir, "ui-token"))
	if err != nil || len(strings.TrimSpace(string(token))) != 43 {
		return errors.New("service readiness: status token is unavailable")
	}
	roots := x509.NewCertPool()
	roots.AddCert(certificate)
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS13}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 3 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, address+"/local/state", nil)
	if err != nil {
		return errors.New("service readiness: invalid local address")
	}
	request.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(token)))
	response, err := client.Do(request)
	if err != nil {
		return errors.New("service readiness: local TLS connection failed")
	}
	defer response.Body.Close()
	var state struct {
		Enabled    *bool  `json:"vpn_enabled"`
		Tunnel     bool   `json:"tunnel"`
		Guard      bool   `json:"guard"`
		PowerError string `json:"power_error"`
	}
	if response.StatusCode != http.StatusOK || json.NewDecoder(io.LimitReader(response.Body, 8<<20)).Decode(&state) != nil || state.Enabled == nil {
		return errors.New("service readiness: status response is not valid")
	}
	if state.PowerError != "" || (*state.Enabled && (!state.Tunnel || !state.Guard)) {
		return errors.New("service readiness: network initialization failed; inspect the service log")
	}
	return nil
}
