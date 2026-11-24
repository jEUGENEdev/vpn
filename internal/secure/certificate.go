package secure

import (
	"crypto/tls"
	"os"
	"sync"
	"time"
)

// CertificateLoader reloads a renewed certificate without restarting VPN flows.
// The service reads root-owned files; this does not generate or rotate keys.
func CertificateLoader(certPath, keyPath string) (func(*tls.ClientHelloInfo) (*tls.Certificate, error), error) {
	initial, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, err
	}
	var mu sync.Mutex
	current := &initial
	var stamp time.Time
	return func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
		mu.Lock()
		defer mu.Unlock()
		info, err := os.Stat(certPath)
		if err != nil {
			return nil, err
		}
		if info.ModTime() != stamp {
			next, err := tls.LoadX509KeyPair(certPath, keyPath)
			if err != nil {
				return nil, err
			}
			current = &next
			stamp = info.ModTime()
		}
		return current, nil
	}, nil
}
