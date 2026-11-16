package server

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jEUGENEdev/vpn/internal/secure"
	"github.com/jEUGENEdev/vpn/internal/store"
	"github.com/jEUGENEdev/vpn/internal/transport"
)

func bootstrapCertificate(t *testing.T, ip string, expires time.Time) ([]byte, *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Test API"},
		IPAddresses: []net.IP{net.ParseIP(ip)}, NotBefore: time.Now().Add(-time.Hour), NotAfter: expires,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), cert
}

func TestAdminBootstrapUsesConfiguredServerAndCurrentCertificate(t *testing.T) {
	for _, tc := range []struct{ ip, listen, authority string }{
		{"8.8.8.8", ":8443", "8.8.8.8:8443"},
		{"2001:4860:4860::8888", "[::]:9443", "[2001:4860:4860::8888]:9443"},
	} {
		t.Run(tc.ip, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "api-cert.pem")
			raw, cert := bootstrapCertificate(t, tc.ip, time.Now().Add(time.Hour))
			if err := os.WriteFile(path, raw, 0600); err != nil {
				t.Fatal(err)
			}
			s := &Server{Config: Config{PublicIP: tc.ip, Address: tc.listen, Cert: path,
				Key: "private-api-key", AdminPasswordFile: "admin-password",
				Transport: transport.ServerOptions{PrivateKey: "private-reality-key"}},
				admins: map[string]session{secure.Hash("admin-token"): {expires: time.Now().Add(time.Hour)},
					secure.Hash("expired-admin"): {expires: time.Now().Add(-time.Minute)}},
				Apply: func(store.State) error { t.Fatal("retrieval must not restart VPN"); return nil }}
			h := s.Handler(nil)
			request := func(token string) *httptest.ResponseRecorder {
				r := httptest.NewRequest("GET", "/api/admin/bootstrap", nil)
				r.Host = "untrusted.example:1234"
				r.Header.Set("X-Forwarded-Host", "untrusted.example:1234")
				r.Header.Set("Authorization", "Bearer "+token)
				w := httptest.NewRecorder()
				h.ServeHTTP(w, r)
				return w
			}
			for _, token := range []string{"", "device-token", "expired-admin"} {
				if w := request(token); w.Code != 401 || strings.Contains(w.Body.String(), "linevpn://") {
					t.Fatalf("profile exposed without an admin session: %d %s", w.Code, w.Body.String())
				}
			}
			check := func(expected string) {
				t.Helper()
				w := request("admin-token")
				var response map[string]string
				if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
					t.Fatal(err)
				}
				if w.Code != 200 || len(response) != 1 || response["profile"] != expected {
					t.Fatalf("unexpected bootstrap response: %d %s", w.Code, w.Body.String())
				}
				if w.Header().Get("Cache-Control") != "no-store" {
					t.Fatal("admin profile was cacheable")
				}
			}
			want := "linevpn://" + tc.authority + "?pin=" + secure.Pin(cert)
			check(want)
			check(want)
			after, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(raw, after) {
				t.Fatal("retrieval changed the server certificate")
			}
			// A changed certificate must be reflected immediately, without a stale file/profile cache.
			replacement, newCert := bootstrapCertificate(t, tc.ip, time.Now().Add(time.Hour))
			if err := os.WriteFile(path, replacement, 0600); err != nil {
				t.Fatal(err)
			}
			check("linevpn://" + tc.authority + "?pin=" + secure.Pin(newCert))
		})
	}
}

func TestAdminBootstrapRejectsUnusableCertificate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "api-cert.pem")
	s := &Server{Config: Config{PublicIP: "8.8.8.8", Address: ":8443", Cert: path},
		admins: map[string]session{secure.Hash("admin-token"): {expires: time.Now().Add(time.Hour)}}}
	expired, _ := bootstrapCertificate(t, "8.8.8.8", time.Now().Add(-time.Minute))
	wrongHost, _ := bootstrapCertificate(t, "1.1.1.1", time.Now().Add(time.Hour))
	for _, raw := range [][]byte{nil, []byte("not a certificate"), expired, wrongHost} {
		if raw != nil {
			if err := os.WriteFile(path, raw, 0600); err != nil {
				t.Fatal(err)
			}
		}
		r := httptest.NewRequest("GET", "/api/admin/bootstrap", nil)
		r.Header.Set("Authorization", "Bearer admin-token")
		w := httptest.NewRecorder()
		s.Handler(nil).ServeHTTP(w, r)
		if w.Code != 503 || strings.Contains(w.Body.String(), "linevpn://") || strings.Contains(w.Body.String(), path) {
			t.Fatalf("unusable certificate returned a profile or leaked a path: %d %s", w.Code, w.Body.String())
		}
	}
}
