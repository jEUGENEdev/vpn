package desktopcontrol

import (
	"crypto/x509"
	"testing"
)

func TestLocalCertificateIsAValidTrustAnchor(t *testing.T) {
	channel, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer channel.Listener.Close()
	certificate, err := x509.ParseCertificate(channel.TLS.Certificates[0].Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	// Electron/BoringSSL requires a proper trust anchor in its explicit CA
	// list. OpenSSL and Go accepting a pinned leaf does not prove compatibility.
	if err := certificate.CheckSignatureFrom(certificate); err != nil {
		t.Fatal("local certificate cannot authenticate its own chain", err)
	}
	if err := certificate.VerifyHostname("127.0.0.1"); err != nil {
		t.Fatal(err)
	}
}
