package secure

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCertificateLoaderRenewsWithoutChangingPinOrListener(t *testing.T) {
	dir := t.TempDir()
	cp, kp := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	if err = Save(kp, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: raw})); err != nil {
		t.Fatal(err)
	}
	writeCert := func(serial int64) *x509.Certificate {
		t.Helper()
		c := &x509.Certificate{SerialNumber: big.NewInt(serial), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
		der, err := x509.CreateCertificate(rand.Reader, c, c, &key.PublicKey, key)
		if err != nil {
			t.Fatal(err)
		}
		if err = Save(cp, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})); err != nil {
			t.Fatal(err)
		}
		stamp := time.Unix(1700000000+serial, 0)
		if err = os.Chtimes(cp, stamp, stamp); err != nil {
			t.Fatal(err)
		}
		parsed, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		return parsed
	}
	original := writeCert(1)
	loader, err := CertificateLoader(cp, kp)
	if err != nil {
		t.Fatal(err)
	}
	s := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }))
	s.TLS = &tls.Config{MinVersion: tls.VersionTLS13, GetCertificate: loader}
	s.StartTLS()
	defer s.Close()
	// httptest inserts its own static certificate even when GetCertificate is set.
	// Match production ServeTLS("", ""): an IP client sends no SNI.
	s.TLS.Certificates = nil
	client := HTTPClient(Pin(original))
	defer client.CloseIdleConnections()
	get := func(serial int64) {
		t.Helper()
		client.CloseIdleConnections()
		resp, err := client.Get(s.URL)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.TLS.PeerCertificates[0].SerialNumber.Int64() != serial {
			t.Fatal("stale certificate served")
		}
	}
	get(1)
	writeCert(2)
	get(2)
}
