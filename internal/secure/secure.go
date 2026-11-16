package secure

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

func Token() string {
	b := make([]byte, 32)
	if _, e := rand.Read(b); e != nil {
		panic(e)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
func UUID() string {
	b := make([]byte, 16)
	if _, e := rand.Read(b); e != nil {
		panic(e)
	}
	b[6] = (b[6] & 15) | 64
	b[8] = (b[8] & 63) | 128
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[:4], b[4:6], b[6:8], b[8:10], b[10:])
}
func Hash(s string) string   { v := sha256.Sum256([]byte(s)); return hex.EncodeToString(v[:]) }
func Equal(a, b string) bool { return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1 }
func Pin(cert *x509.Certificate) string {
	s := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return base64.RawURLEncoding.EncodeToString(s[:])
}
func HTTPClient(pin string) *http.Client {
	return &http.Client{Timeout: 20 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("redirects prohibited") }, Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, InsecureSkipVerify: true, VerifyConnection: func(c tls.ConnectionState) error {
		if len(c.PeerCertificates) == 0 || pin == "" || !Equal(Pin(c.PeerCertificates[0]), pin) {
			return errors.New("сертификат сервера не совпадает с профилем")
		}
		cert := c.PeerCertificates[0]
		if time.Now().Before(cert.NotBefore) || time.Now().After(cert.NotAfter) {
			return errors.New("сертификат просрочен")
		}
		return nil
	}}}}
}

// Save persists before publishing new policy. Existing files are never relaxed.
func Save(path string, data []byte) error {
	if e := os.MkdirAll(filepath.Dir(path), 0700); e != nil {
		return e
	}
	f, e := os.CreateTemp(filepath.Dir(path), ".pending-*")
	if e != nil {
		return e
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if e = f.Chmod(0600); e == nil {
		_, e = f.Write(data)
	}
	if e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e == nil {
		e = ce
	}
	if e != nil {
		return e
	}
	return os.Rename(tmp, path)
}
