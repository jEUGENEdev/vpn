package main

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"github.com/jEUGENEdev/vpn/internal/secure"
	"github.com/jEUGENEdev/vpn/internal/server"
	"github.com/jEUGENEdev/vpn/internal/transport"
	"io"
	"log"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

func main() {
	dir := flag.String("dir", "/etc/linevpn", "configuration directory")
	ip := flag.String("ip", "", "public server IP")
	sni := flag.String("reality-target", "www.microsoft.com", "REALITY handshake destination")
	renew := flag.Bool("renew", false, "renew API certificate using the existing pinned key")
	ensureAdminSAN := flag.Bool("ensure-admin-san", false, "renew an existing certificate only if loopback SANs are missing or renewal is due")
	hashAdmin := flag.Bool("hash-admin-password", false, "hash admin password supplied on stdin")
	migrateAdmin := flag.String("migrate-admin-password", "", "replace legacy admin password file with bcrypt hash")
	publicAdmin := flag.String("public-admin", "", "set true or false to configure public HTTPS administration on an existing server")
	flag.Parse()
	if *publicAdmin != "" {
		enabled, err := strconv.ParseBool(*publicAdmin)
		if err != nil {
			log.Fatal("-public-admin must be true or false")
		}
		changed, err := setPublicAdmin(filepath.Join(*dir, "server.json"), enabled)
		if err != nil {
			log.Fatal(err)
		}
		if changed {
			fmt.Println("changed")
		}
		return
	}
	if *hashAdmin || *migrateAdmin != "" {
		var raw []byte
		var err error
		if *migrateAdmin != "" {
			raw, err = os.ReadFile(*migrateAdmin)
		} else {
			raw, err = io.ReadAll(io.LimitReader(os.Stdin, 1024))
		}
		if err != nil {
			log.Fatal(err)
		}
		value := strings.TrimRight(string(raw), "\r\n")
		hash, err := secure.AdminHash(value)
		if err != nil {
			log.Fatal(err)
		}
		if *migrateAdmin != "" {
			if value != string(hash) {
				if err = secure.Save(*migrateAdmin, hash); err != nil {
					log.Fatal(err)
				}
				fmt.Println("changed")
			}
		} else {
			fmt.Println(string(hash))
		}
		return
	}
	if net.ParseIP(*ip) == nil {
		log.Fatal("-ip must be an IP address")
	}
	if *ensureAdminSAN {
		raw, err := os.ReadFile(filepath.Join(*dir, "api-cert.pem"))
		if err != nil {
			log.Fatal(err)
		}
		if block, _ := pem.Decode(raw); block != nil {
			if cert, err := x509.ParseCertificate(block.Bytes); err == nil && cert.VerifyHostname(*ip) == nil && cert.VerifyHostname("127.0.0.1") == nil && cert.VerifyHostname("::1") == nil && time.Now().Before(cert.NotAfter.Add(-30*24*time.Hour)) {
				return
			}
		}
		*renew = true
	}
	if err := secure.PrepareDirectory(*dir); err != nil {
		log.Fatal(err)
	}
	configPath := filepath.Join(*dir, "server.json")
	if _, e := os.Stat(configPath); e == nil && !*renew {
		log.Fatal("configuration exists; use -renew only for certificate renewal")
	}
	keyPath := filepath.Join(*dir, "api-key.pem")
	var key *ecdsa.PrivateKey
	var err error
	if *renew {
		raw, e := os.ReadFile(keyPath)
		if e != nil {
			log.Fatal(e)
		}
		b, _ := pem.Decode(raw)
		if b == nil {
			log.Fatal("invalid key")
		}
		k, e := x509.ParsePKCS8PrivateKey(b.Bytes)
		if e != nil {
			log.Fatal(e)
		}
		var ok bool
		key, ok = k.(*ecdsa.PrivateKey)
		if !ok {
			log.Fatal("API key must be ECDSA")
		}
	} else {
		key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			log.Fatal(err)
		}
		raw, _ := x509.MarshalPKCS8PrivateKey(key)
		if e := secure.Save(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: raw})); e != nil {
			log.Fatal(e)
		}
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	cert := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "LineVPN API"}, IPAddresses: []net.IP{net.ParseIP(*ip), net.ParseIP("127.0.0.1"), net.ParseIP("::1")}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(365 * 24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true}
	der, e := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if e != nil {
		log.Fatal(e)
	}
	certPath := filepath.Join(*dir, "api-cert.pem")
	if e = secure.Save(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})); e != nil {
		log.Fatal(e)
	}
	parsed, _ := x509.ParseCertificate(der)
	if !*renew {
		rk, e := ecdh.X25519().GenerateKey(rand.Reader)
		if e != nil {
			log.Fatal(e)
		}
		sid := make([]byte, 8)
		rand.Read(sid)
		listen := "0.0.0.0"
		if net.ParseIP(*ip).To4() == nil {
			listen = "::"
		}
		cfg := server.Config{Address: ":8443", AdminAddress: "127.0.0.1:8444", PublicIP: *ip, Database: "/var/lib/linevpn/server.db", Cert: certPath, Key: keyPath, AdminPasswordFile: filepath.Join(*dir, "admin-password"), Transport: transport.ServerOptions{Listen: listen, Port: 443, PrivateKey: base64.RawURLEncoding.EncodeToString(rk.Bytes()), PublicKey: base64.RawURLEncoding.EncodeToString(rk.PublicKey().Bytes()), SNI: *sni, Target: net.JoinHostPort(*sni, "443"), ShortID: fmt.Sprintf("%x", sid), Path: "/line/" + secure.Token()[:24]}}
		raw, _ := json.MarshalIndent(cfg, "", "  ")
		if e = secure.Save(configPath, raw); e != nil {
			log.Fatal(e)
		}
	}
	fmt.Printf("linevpn://%s?pin=%s\n", net.JoinHostPort(*ip, "8443"), secure.Pin(parsed))
}
