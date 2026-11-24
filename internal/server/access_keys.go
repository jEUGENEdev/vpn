package server

import (
	"encoding/base64"
	"errors"
	"fmt"
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

func revokeAccountDevices(st *store.State, account string) {
	for id, d := range st.Devices {
		if d.AccountID == account {
			d.Revoked = true
			d.RevokedAt = time.Now()
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
	var caller store.Device
	var account string
	if admin {
		if !s.admin(r) {
			fail(w, 401, ErrForbidden)
			return
		}
	} else {
		d, a, err := s.device(r)
		if err != nil {
			fail(w, 401, err)
			return
		}
		caller, account = d, a.ID
		if s.limitedKey("rotate:"+account, 5, time.Hour) {
			fail(w, 429, errors.New("слишком много попыток замены ключа"))
			return
		}
	}
	var input struct {
		ID         string `json:"id"`
		CurrentKey string `json:"current_key"`
		Confirm    bool   `json:"confirm"`
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
		if !admin && !stillAuthorized(st, caller) {
			return ErrForbidden
		}
		a, ok := st.Accounts[account]
		if !ok {
			return ErrForbidden
		}
		if !admin && (!validAccessKey(strings.TrimSpace(input.CurrentKey)) || !secure.Equal(a.KeyHash, secure.Hash(strings.TrimSpace(input.CurrentKey)))) {
			return ErrForbidden
		}
		login = a.Login
		a.KeyHash, a.Hash = secure.Hash(key), ""
		a.Revision++
		st.Accounts[account] = a
		revokeAccountDevices(st, account)
		return nil
	})
	if err != nil && !errors.Is(err, errApplyPending) {
		if errors.Is(err, ErrForbidden) {
			fail(w, 403, ErrForbidden)
			return
		}
		fail(w, 503, errors.New("не удалось завершить замену ключа; повторите выпуск через администратора"))
		return
	}
	JSON(w, 200, map[string]string{"access_key": key, "login": login, "vpn_apply_pending": fmt.Sprint(errors.Is(err, errApplyPending))})
}
