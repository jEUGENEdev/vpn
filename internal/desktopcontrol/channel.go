package desktopcontrol

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"github.com/jEUGENEdev/vpn/internal/secure"
)

type Credentials struct {
	Certificate string `json:"certificate"`
	Address     string `json:"address"`
	Token       string `json:"token"`
	Pin         string `json:"pin"`
}
type Channel struct {
	TLS         *tls.Config
	Listener    net.Listener
	Credentials Credentials
}

// Open binds the endpoint before publishing its credentials. A loopback port
// impostor cannot receive the administrative token: the helper pins this fresh
// certificate, whose private key only exists in service memory.
func Open(dir string) (*Channel, error) {
	private := filepath.Join(dir, "control")
	if err := privateDirectory(private); err != nil {
		return nil, err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}
	// This self-signed certificate is the explicit trust anchor used by the
	// desktop TLS client. Electron/BoringSSL rejects a leaf without CA/key-sign
	// constraints here, even though Go and OpenSSL accept that same pinned leaf.
	template := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "Set local control"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().AddDate(10, 0, 0), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, BasicConstraintsValid: true, IsCA: true, MaxPathLenZero: true, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	credentials := Credentials{Certificate: base64.StdEncoding.EncodeToString(der), Address: "https://" + listener.Addr().String(), Token: secure.Token(), Pin: secure.Pin(cert)}
	encoded, err := json.Marshal(credentials)
	if err == nil {
		err = secure.Save(filepath.Join(private, "session.json"), encoded)
	}
	if err != nil {
		listener.Close()
		return nil, err
	}
	config := &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
	return &Channel{Listener: tls.NewListener(listener, config), Credentials: credentials, TLS: config}, nil
}

func ReadCredentials(path string) (Credentials, error) {
	var result Credentials
	f, err := os.Open(path)
	if err != nil {
		return result, err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, 4097))
	if err != nil || len(raw) > 4096 {
		return result, errors.New("invalid control session")
	}
	if json.Unmarshal(raw, &result) != nil {
		return result, errors.New("invalid control session")
	}
	u, err := url.Parse(result.Address)
	if err != nil || u.Scheme != "https" || u.Hostname() != "127.0.0.1" || u.Port() == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || len(result.Token) != 43 || len(result.Pin) != 43 {
		return Credentials{}, errors.New("invalid control session")
	}
	return result, nil
}

// Approve executes at most the reviewed immutable command, after native consent.
// It never returns command data (including account keys) to stdout or argv.
func Approve(ctx context.Context, credentials Credentials, id string, confirm func(string) bool) error {
	if len(id) != 43 {
		return errors.New("invalid request")
	}
	for _, r := range id {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' || r == '-') {
			return errors.New("invalid request")
		}
	}
	client := secure.HTTPClient(credentials.Pin)
	defer client.CloseIdleConnections()
	call := func(method, path string, data any) ([]byte, error) {
		var body io.Reader
		if data != nil {
			raw, e := json.Marshal(data)
			if e != nil {
				return nil, e
			}
			body = bytes.NewReader(raw)
		}
		req, e := http.NewRequestWithContext(ctx, method, credentials.Address+path+"?id="+url.QueryEscape(id), body)
		if e != nil {
			return nil, e
		}
		req.Header.Set("Authorization", "Bearer "+credentials.Token)
		req.Header.Set("Content-Type", "application/json")
		res, e := client.Do(req)
		if e != nil {
			return nil, errors.New("служба управления недоступна или не прошла проверку")
		}
		defer res.Body.Close()
		raw, e := io.ReadAll(io.LimitReader(res.Body, 8192))
		if e != nil {
			return nil, e
		}
		if res.StatusCode != 200 {
			return nil, errors.New("команда истекла или отклонена службой")
		}
		return raw, nil
	}
	raw, err := call("GET", "/review", nil)
	if err != nil {
		return err
	}
	var review struct {
		Summary string `json:"summary"`
		Digest  string `json:"digest"`
	}
	if json.Unmarshal(raw, &review) != nil || review.Summary == "" || len(review.Summary) > 3000 || len(review.Digest) != 64 {
		return errors.New("invalid review")
	}
	if !confirm(review.Summary) {
		_, _ = call("POST", "/cancel", map[string]string{"digest": review.Digest})
		return errors.New("изменение отменено")
	}
	_, err = call("POST", "/commit", map[string]string{"digest": review.Digest})
	return err
}
