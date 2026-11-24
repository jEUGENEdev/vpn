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
	"io"
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

var (
	ErrPinMismatch            = errors.New("сертификат сервера не совпадает с профилем")
	ErrCertificateNotYetValid = errors.New("сертификат сервера ещё не действует; проверьте дату и время устройства")
	ErrCertificateExpired     = errors.New("сертификат сервера истёк; требуется продление на сервере")
	ErrRedirect               = errors.New("redirects prohibited")
)

func HTTPClient(pin string) *http.Client {
	return &http.Client{
		Timeout:       20 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return ErrRedirect },
		Transport: &http.Transport{
			TLSHandshakeTimeout:   10 * time.Second,
			ResponseHeaderTimeout: 15 * time.Second,
			IdleConnTimeout:       60 * time.Second,
			MaxIdleConns:          8,
			MaxIdleConnsPerHost:   2,
			TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, InsecureSkipVerify: true, VerifyConnection: func(c tls.ConnectionState) error {
				if len(c.PeerCertificates) == 0 || pin == "" || !Equal(Pin(c.PeerCertificates[0]), pin) {
					return ErrPinMismatch
				}
				cert := c.PeerCertificates[0]
				now := time.Now()
				if now.Before(cert.NotBefore) {
					return ErrCertificateNotYetValid
				}
				if now.After(cert.NotAfter) {
					return ErrCertificateExpired
				}
				return nil
			}},
		},
	}
}

// PrepareDirectory permits intentional traversal of desktop state, but rejects
// a writable/symlinked leaf directory. Individual secret files get private ACLs.
func PrepareDirectory(path string) error {
	if err := os.MkdirAll(path, 0700); err != nil {
		return err
	}
	return checkDirectory(path)
}

// OpenPrivateFile is also used by bbolt: its creation mode alone does not fix
// existing files or Windows inherited ACLs. Tighten access before reading state.
func OpenPrivateFile(path string, flag int, mode os.FileMode) (*os.File, error) {
	if err := PrepareDirectory(filepath.Dir(path)); err != nil {
		return nil, err
	}
	if info, err := os.Lstat(path); err == nil && !info.Mode().IsRegular() {
		return nil, errors.New("secret file must be a regular file")
	} else if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	f, err := os.OpenFile(path, flag, mode)
	if err != nil {
		return nil, err
	}
	if err = protectFile(f); err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}

// ReadPrivateFile also repairs legacy file permissions before loading secrets.
func ReadPrivateFile(path string) ([]byte, error) {
	f, err := OpenPrivateFile(path, os.O_RDONLY, 0600)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(f)
}

// Save persists before publishing new policy. Existing files are never relaxed.
func Save(path string, data []byte) error {
	if e := PrepareDirectory(filepath.Dir(path)); e != nil {
		return e
	}
	f, e := os.CreateTemp(filepath.Dir(path), ".pending-*")
	if e != nil {
		return e
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if e = protectFile(f); e == nil {
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
	if e = os.Rename(tmp, path); e != nil {
		return e
	}
	return syncDirectory(filepath.Dir(path))
}
