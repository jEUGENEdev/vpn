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
	"github.com/jEUGENEdev/vpn/internal/store"
)

// bootstrapBaseURI describes the existing server. It must never rotate keys or
// restart the transport when an administrator copies a connection profile.
func (s *Server) bootstrapBaseURI() (string, error) {
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

var errBootstrap = errors.New("профиль сервера отозван или устарел; импортируйте новый профиль из админки")

func checkBootstrap(st store.State, r *http.Request) error {
	if st.BootstrapKey == "" || !secure.Equal(st.BootstrapKey, r.Header.Get("X-LineVPN-Profile")) {
		return errBootstrap
	}
	return nil
}

func (s *Server) bootstrapURI() (string, error) {
	base, err := s.bootstrapBaseURI()
	if err != nil {
		return "", err
	}
	var key string
	err = s.Store.View(func(st store.State) error { key = st.BootstrapKey; return nil })
	if err != nil {
		return "", err
	}
	if key == "" {
		return "", errBootstrap
	}
	return base + "&access=" + key, nil
}

// Rotation gates future enrollment. Existing sessions survive unless explicitly
// revoked. TLS/REALITY keys are not leaked by a bootstrap URI and stay unchanged.
func (s *Server) adminRotateBootstrap(w http.ResponseWriter, r *http.Request) {
	if !s.admin(r) {
		fail(w, 401, ErrForbidden)
		return
	}
	var input struct {
		Confirm       bool `json:"confirm"`
		RevokeDevices bool `json:"revoke_devices"`
	}
	if !body(w, r, &input) {
		return
	}
	if !input.Confirm {
		fail(w, 400, errors.New("подтвердите отзыв старого профиля"))
		return
	}
	base, err := s.bootstrapBaseURI()
	if err != nil {
		fail(w, 503, errors.New("проверьте адрес API и сертификат перед перевыпуском"))
		return
	}
	s.change.Lock()
	defer s.change.Unlock()
	key := secure.Token()
	err = s.Store.Update(func(st *store.State) error {
		st.BootstrapKey = key
		st.Pairs = map[string]store.Pair{}
		if input.RevokeDevices {
			for id, device := range st.Devices {
				device.Revoked = true
				st.Devices[id] = device
			}
		}
		return nil
	})
	if err == nil && input.RevokeDevices && s.Apply != nil {
		err = s.Store.View(s.Apply)
	}
	if err != nil {
		fail(w, 503, errors.New("не удалось завершить перевыпуск; проверьте сервер и заново получите текущий профиль"))
		return
	}
	JSON(w, 200, map[string]string{"profile": base + "&access=" + key})
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
