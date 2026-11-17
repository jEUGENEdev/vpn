package server

import (
	"encoding/base64"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/jEUGENEdev/vpn/internal/secure"
	"github.com/jEUGENEdev/vpn/internal/store"
)

var errAccessKey = errors.New("неверный или отозванный ключ доступа")
var errAccountInactive = errors.New("аккаунт ещё не одобрен или заблокирован")

func newAccessKey() string { return "lnv_" + secure.Token() }
func validAccessKey(key string) bool {
	if !strings.HasPrefix(key, "lnv_") || len(key) != 47 {
		return false
	}
	raw, err := base64.RawURLEncoding.DecodeString(key[4:])
	return err == nil && len(raw) == 32
}

func deviceActive(st store.State, id string) bool {
	d, ok := st.Devices[id]
	return ok && !d.Revoked && time.Now().Before(d.Expires) && st.Accounts[d.AccountID].Status == "active"
}

func revokeAccountDevices(st *store.State, account string) {
	for id, d := range st.Devices {
		if d.AccountID == account {
			d.Revoked = true
			st.Devices[id] = d
		}
	}
	for key, pair := range st.Pairs {
		if pair.AccountID == account {
			delete(st.Pairs, key)
		}
	}
}

func (s *Server) adminAccessKey(w http.ResponseWriter, r *http.Request) {
	s.replaceAccessKey(w, r, true)
}
func (s *Server) rotateAccessKey(w http.ResponseWriter, r *http.Request) {
	s.replaceAccessKey(w, r, false)
}

func (s *Server) replaceAccessKey(w http.ResponseWriter, r *http.Request, admin bool) {
	var deviceID, account string
	if admin {
		if !s.admin(r) {
			fail(w, 401, ErrForbidden)
			return
		}
	} else {
		d, a, err := s.device(r)
		if err != nil {
			fail(w, 401, ErrForbidden)
			return
		}
		deviceID, account = d.ID, a.ID
	}
	var input struct {
		ID      string `json:"id"`
		Confirm bool   `json:"confirm"`
	}
	if !body(w, r, &input) {
		return
	}
	if !input.Confirm {
		fail(w, 400, errors.New("подтвердите отзыв старого ключа и всех устройств аккаунта"))
		return
	}
	if admin {
		account = input.ID
	} else if input.ID != "" && input.ID != account {
		fail(w, 403, ErrForbidden)
		return
	}
	key, login := newAccessKey(), ""
	err := s.mutation(func(st *store.State) error {
		if !admin && !deviceActive(*st, deviceID) {
			return ErrForbidden
		}
		a, ok := st.Accounts[account]
		if !ok {
			return ErrForbidden
		}
		login = a.Login
		a.KeyHash, a.Hash = secure.Hash(key), ""
		a.Revision++
		st.Accounts[account] = a
		revokeAccountDevices(st, account)
		return nil
	})
	if err != nil {
		if errors.Is(err, ErrForbidden) {
			fail(w, 403, ErrForbidden)
			return
		}
		fail(w, 503, errors.New("не удалось завершить замену ключа; повторите выпуск через администратора"))
		return
	}
	JSON(w, 200, map[string]string{"access_key": key, "login": login})
}
