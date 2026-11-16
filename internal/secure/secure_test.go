package secure

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestPinnedTLS(t *testing.T) {
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) }))
	defer s.Close()
	pin := Pin(s.Certificate())
	client := HTTPClient(pin)
	r, e := client.Get(s.URL)
	if e != nil {
		t.Fatal(e)
	}
	r.Body.Close()
	for _, wrong := range []string{"", Token()} {
		if r, e := HTTPClient(wrong).Get(s.URL); e == nil {
			r.Body.Close()
			t.Fatal("wrong pin accepted")
		}
	}
	cert := *s.Certificate()
	cert.NotAfter = time.Now().Add(-time.Minute)
	verify := client.Transport.(*http.Transport).TLSClientConfig.VerifyConnection
	if e := verify(tls.ConnectionState{PeerCertificates: []*x509.Certificate{}}); e == nil {
		t.Fatal("missing cert accepted")
	}
	if e := verify(tls.ConnectionState{PeerCertificates: []*x509.Certificate{&cert}}); e == nil {
		t.Fatal("expired certificate accepted")
	}
}
