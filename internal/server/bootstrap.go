package server

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/jEUGENEdev/vpn/internal/secure"
)

// bootstrapURI describes the existing server. It must never rotate keys or
// restart the transport when an administrator copies a connection profile.
func (s *Server) bootstrapURI() (string, error) {
	ip := net.ParseIP(s.Config.PublicIP)
	_, port, err := net.SplitHostPort(s.Config.Address)
	if err != nil || ip == nil {
		return "", errors.New("invalid API address")
	}
	n, err := strconv.ParseUint(port, 10, 16)
	if err != nil || n == 0 {
		return "", errors.New("invalid API port")
	}
	raw, err := os.ReadFile(s.Config.Cert)
	if err != nil {
		return "", err
	}
	block, _ := pem.Decode(raw)
	if block == nil || block.Type != "CERTIFICATE" {
		return "", errors.New("invalid API certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", err
	}
	if err = cert.VerifyHostname(ip.String()); err != nil {
		return "", err
	}
	now := time.Now()
	if now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
		return "", errors.New("API certificate is not currently valid")
	}
	return "linevpn://" + net.JoinHostPort(ip.String(), strconv.FormatUint(n, 10)) + "?pin=" + secure.Pin(cert), nil
}

func (s *Server) adminBootstrap(w http.ResponseWriter, r *http.Request) {
	if !s.admin(r) {
		fail(w, http.StatusUnauthorized, ErrForbidden)
		return
	}
	profile, err := s.bootstrapURI()
	if err != nil {
		fail(w, http.StatusServiceUnavailable, errors.New("профиль сервера недоступен: проверьте адрес API и сертификат"))
		return
	}
	JSON(w, http.StatusOK, map[string]string{"profile": profile})
}
