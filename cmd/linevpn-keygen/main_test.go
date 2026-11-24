package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/jEUGENEdev/vpn/internal/secure"
)

func TestKeygenProcess(t *testing.T) {
	if os.Getenv("LINEVPN_KEYGEN_TEST_PROCESS") != "1" {
		return
	}
	for i, arg := range os.Args {
		if arg == "--" {
			os.Args = append([]string{os.Args[0]}, os.Args[i+1:]...)
			break
		}
	}
	flag.CommandLine = flag.NewFlagSet("keygen", flag.ExitOnError)
	main()
	os.Exit(0)
}

func TestRenewalAndLoopbackUpgradePreserveIdentity(t *testing.T) {
	dir := t.TempDir()
	run := func(args ...string) []byte {
		t.Helper()
		cmd := exec.Command(os.Args[0], append([]string{"-test.run=^TestKeygenProcess$", "--", "-dir", dir, "-ip", "203.0.113.7"}, args...)...)
		cmd.Env = append(os.Environ(), "LINEVPN_KEYGEN_TEST_PROCESS=1")
		output, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("keygen: %v: %s", err, output)
		}
		return output
	}
	read := func(name string) []byte {
		t.Helper()
		raw, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	cert := func() *x509.Certificate {
		t.Helper()
		block, _ := pem.Decode(read("api-cert.pem"))
		if block == nil {
			t.Fatal("missing certificate")
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	run()
	key, config := read("api-key.pem"), read("server.json")
	original := cert()
	pin := secure.Pin(original)
	// Simulate the old public-IP-only certificate on an existing installation.
	block, _ := pem.Decode(key)
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	private := parsed.(*ecdsa.PrivateKey)
	legacy := *original
	legacy.IPAddresses = []net.IP{net.ParseIP("203.0.113.7")}
	legacy.NotAfter = time.Now().Add(48 * time.Hour)
	der, err := x509.CreateCertificate(rand.Reader, &legacy, &legacy, &private.PublicKey, private)
	if err != nil {
		t.Fatal(err)
	}
	if err = secure.Save(filepath.Join(dir, "api-cert.pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})); err != nil {
		t.Fatal(err)
	}
	if len(run("-ensure-admin-san")) == 0 {
		t.Fatal("legacy certificate was not upgraded")
	}
	upgraded := cert()
	for _, ip := range []string{"203.0.113.7", "127.0.0.1", "::1"} {
		if err := upgraded.VerifyHostname(ip); err != nil {
			t.Fatal(err)
		}
	}
	if secure.Pin(upgraded) != pin {
		t.Fatal("upgrade changed pinned identity")
	}
	if len(run("-ensure-admin-san")) != 0 {
		t.Fatal("unchanged certificate was unnecessarily renewed")
	}
	run("-renew")
	renewed := cert()
	if secure.Pin(renewed) != pin || renewed.SerialNumber.Cmp(upgraded.SerialNumber) == 0 {
		t.Fatal("renewal did not retain identity with a fresh certificate")
	}
	if !bytes.Equal(key, read("api-key.pem")) || !bytes.Equal(config, read("server.json")) {
		t.Fatal("renewal changed keys/configuration")
	}
}
