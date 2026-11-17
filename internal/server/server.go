package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/jEUGENEdev/vpn/internal/model"
	"github.com/jEUGENEdev/vpn/internal/policy"
	"github.com/jEUGENEdev/vpn/internal/secure"
	"github.com/jEUGENEdev/vpn/internal/store"
	"github.com/jEUGENEdev/vpn/internal/transport"
	"golang.org/x/crypto/bcrypt"
)

type Config struct {
	Address           string                  `json:"address"`
	PublicIP          string                  `json:"public_ip"`
	Database          string                  `json:"database"`
	Cert              string                  `json:"cert"`
	Key               string                  `json:"key"`
	AdminPasswordFile string                  `json:"admin_password_file"`
	Transport         transport.ServerOptions `json:"transport"`
}
type session struct{ expires time.Time }
type bucket struct {
	at    time.Time
	count int
}
type Server struct {
	Store     *store.Store
	Config    Config
	Apply     func(store.State) error
	change    sync.Mutex
	mu        sync.Mutex
	admins    map[string]session
	attempts  map[string]bucket
	adminHash []byte
}

var ErrForbidden = errors.New("доступ запрещён")

const maxDiscoveryRequests = 1000
const maxDismissedTargets = 1000

var errDismissedLimit = errors.New("достигнут лимит сохранённых решений «Оставить напрямую» (1000)")

func New(st *store.Store, c Config, password string, apply func(store.State) error) (*Server, error) {
	if len(password) < 16 || len(password) > 72 {
		return nil, errors.New("пароль администратора должен содержать 16–72 байта")
	}
	hash, e := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if e != nil {
		return nil, e
	}
	if e = st.Update(func(state *store.State) error {
		if state.BootstrapKey == "" {
			state.BootstrapKey = secure.Token()
		}
		return nil
	}); e != nil {
		return nil, e
	}
	return &Server{Store: st, Config: c, Apply: apply, admins: map[string]session{}, attempts: map[string]bucket{}, adminHash: hash}, nil
}
func JSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}
func fail(w http.ResponseWriter, status int, e error) {
	JSON(w, status, map[string]string{"error": e.Error()})
}
func body(w http.ResponseWriter, r *http.Request, v any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 32768)
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if e := d.Decode(v); e != nil {
		fail(w, 400, errors.New("некорректный запрос"))
		return false
	}
	return true
}
func (s *Server) limited(r *http.Request, kind string, limit int, window time.Duration) bool {
	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	key := kind + ":" + ip
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	b := s.attempts[key]
	if now.Sub(b.at) > window {
		b = bucket{at: now}
	}
	b.count++
	s.attempts[key] = b
	if len(s.attempts) > 8192 {
		for k, v := range s.attempts {
			if now.Sub(v.at) > time.Hour {
				delete(s.attempts, k)
			}
		}
	}
	return b.count > limit
}
func (s *Server) mutation(fn func(*store.State) error) error {
	s.change.Lock()
	defer s.change.Unlock()
	if e := s.Store.Update(fn); e != nil {
		return e
	}
	if s.Apply != nil {
		return s.Store.View(s.Apply)
	}
	return nil
}
func (s *Server) Refresh() error { return s.mutation(func(*store.State) error { return nil }) }

// Expire revokes each expired device once; periodic checks must not restart
// every active user's transport repeatedly after the first expired session.
func (s *Server) Expire(now time.Time) error {
	s.change.Lock()
	defer s.change.Unlock()
	changed := false
	if e := s.Store.Update(func(st *store.State) error {
		for id, d := range st.Devices {
			if !d.Revoked && !now.Before(d.Expires) {
				d.Revoked = true
				st.Devices[id] = d
				changed = true
			}
		}
		return nil
	}); e != nil {
		return e
	}
	if changed && s.Apply != nil {
		return s.Store.View(s.Apply)
	}
	return nil
}
func bearer(r *http.Request) string {
	return strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
}
func (s *Server) admin(r *http.Request) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.admins[secure.Hash(bearer(r))]
	return ok && time.Now().Before(v.expires)
}
func (s *Server) device(r *http.Request) (store.Device, store.Account, error) {
	var d store.Device
	var a store.Account
	found := false
	h := secure.Hash(bearer(r))
	e := s.Store.View(func(st store.State) error {
		for _, v := range st.Devices {
			if secure.Equal(v.Hash, h) && !v.Revoked && time.Now().Before(v.Expires) {
				d = v
				a = st.Accounts[d.AccountID]
				found = a.Status == "active"
				break
			}
		}
		return nil
	})
	if e != nil {
		return d, a, e
	}
	if !found {
		return d, a, ErrForbidden
	}
	return d, a, nil
}
func (s *Server) profile(d store.Device, a store.Account, token string) model.Profile {
	o := s.Config.Transport
	return model.Profile{Login: a.Login, DeviceID: d.ID, AccountID: a.ID, Token: token, Server: s.Config.PublicIP, Port: o.Port, UUID: d.Secret, AppUUID: d.AppSecret, SNI: o.SNI, PublicKey: o.PublicKey, ShortID: o.ShortID, Path: o.Path, Rules: a.Rules, Revision: a.Revision, Status: a.Status}
}

func (s *Server) Handler(static http.Handler) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { JSON(w, 200, map[string]string{"status": "ok"}) })
	mux.HandleFunc("POST /api/register", s.register)
	mux.HandleFunc("POST /api/login", s.login)
	mux.HandleFunc("POST /api/pair/claim", s.claim)
	mux.HandleFunc("POST /api/admin/login", s.adminLogin)
	mux.HandleFunc("GET /api/admin/bootstrap", s.adminBootstrap)
	mux.HandleFunc("POST /api/admin/bootstrap/rotate", s.adminRotateBootstrap)
	mux.HandleFunc("POST /api/admin/access-key", s.adminAccessKey)
	mux.HandleFunc("POST /api/access-key/rotate", s.rotateAccessKey)
	mux.HandleFunc("GET /api/admin/accounts", s.adminAccounts)
	mux.HandleFunc("POST /api/admin/account", s.adminAccount)
	mux.HandleFunc("POST /api/admin/revoke", s.adminRevoke)
	mux.HandleFunc("POST /api/admin/logout", func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		delete(s.admins, secure.Hash(bearer(r)))
		s.mu.Unlock()
		JSON(w, 200, map[string]bool{"ok": true})
	})
	mux.HandleFunc("GET /api/sync", s.syncState)
	mux.HandleFunc("POST /api/discover", s.discover)
	mux.HandleFunc("POST /api/rules", s.rules)
	mux.HandleFunc("POST /api/app-vpn", s.appVPN)
	mux.HandleFunc("POST /api/dismiss", s.dismiss)
	mux.HandleFunc("POST /api/pair", s.pair)
	mux.HandleFunc("POST /api/revoke", s.revoke)
	if static != nil {
		mux.Handle("/", static)
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
		mux.ServeHTTP(w, r)
	})
}

var loginRE = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{2,63}$`)

type credentials struct {
	deviceChoice
	Login     string `json:"login"`
	AccessKey string `json:"access_key"`
}

func (s *Server) register(w http.ResponseWriter, r *http.Request) {
	if s.limited(r, "register", 5, time.Hour) {
		fail(w, 429, errors.New("слишком много заявок"))
		return
	}
	var c credentials
	if !body(w, r, &c) {
		return
	}
	c.Login = strings.ToLower(strings.TrimSpace(c.Login))
	if !loginRE.MatchString(c.Login) || c.AccessKey != "" {
		fail(w, 400, errors.New("имя аккаунта: 3–64 символа a–z, 0–9, точка, дефис или подчёркивание; ключ выдаётся сервером"))
		return
	}
	key := newAccessKey()
	e := s.Store.Update(func(st *store.State) error {
		if err := checkBootstrap(*st, r); err != nil {
			return err
		}
		for _, a := range st.Accounts {
			if a.Login == c.Login {
				return errors.New("логин уже занят")
			}
		}
		if len(st.Accounts) >= 10000 {
			return errors.New("лимит регистраций")
		}
		a := store.Account{Account: model.Account{ID: secure.UUID(), Login: c.Login, Status: "pending", Created: time.Now(), Rules: []string{}, Revision: 1}, KeyHash: secure.Hash(key)}
		st.Accounts[a.ID] = a
		return nil
	})
	if e != nil {
		status := 409
		if errors.Is(e, errBootstrap) {
			status = 401
		}
		fail(w, status, e)
		return
	}
	JSON(w, 202, map[string]string{"status": "pending", "login": c.Login, "access_key": key, "message": "Заявка отправлена. Сохраните ключ: повторно показать его нельзя."})
}
func validDevice(name, platform string) bool {
	return len(strings.TrimSpace(name)) > 0 && len(name) <= 80 && (platform == "android" || platform == "windows" || platform == "darwin" || platform == "linux")
}
func (s *Server) enroll(account, name, platform string) (model.Profile, error) {
	out, err := s.enrollChoice(account, deviceChoice{Name: name, Platform: platform}, "")
	if err != nil {
		return model.Profile{}, err
	}
	profile, ok := out.(model.Profile)
	if !ok {
		return profile, errors.New("нужно выбрать устройство")
	}
	return profile, nil
}
func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	if s.limited(r, "login", 10, 10*time.Minute) {
		fail(w, 429, errors.New("слишком много попыток входа"))
		return
	}
	var c credentials
	if !body(w, r, &c) {
		return
	}
	c.AccessKey = strings.TrimSpace(c.AccessKey)
	if !validAccessKey(c.AccessKey) {
		fail(w, 401, errAccessKey)
		return
	}
	p, e := s.enrollChoiceAuthorized(c.deviceChoice, "", func(st *store.State) (string, error) {
		if err := checkBootstrap(*st, r); err != nil {
			return "", err
		}
		hash := secure.Hash(c.AccessKey)
		for _, a := range st.Accounts {
			if secure.Equal(a.KeyHash, hash) {
				if a.Status != "active" {
					return "", errAccountInactive
				}
				return a.ID, nil
			}
		}
		return "", errAccessKey
	})
	if e != nil {
		status := 503
		if errors.Is(e, errAccessKey) || errors.Is(e, errBootstrap) {
			status = 401
		}
		if errors.Is(e, errAccountInactive) {
			status = 403
		}
		fail(w, status, e)
		return
	}
	JSON(w, 200, p)
}

func (s *Server) adminLogin(w http.ResponseWriter, r *http.Request) {
	if s.limited(r, "admin", 8, 15*time.Minute) {
		fail(w, 429, errors.New("слишком много попыток входа"))
		return
	}
	var c struct {
		Password string `json:"password"`
	}
	if !body(w, r, &c) {
		return
	}
	if bcrypt.CompareHashAndPassword(s.adminHash, []byte(c.Password)) != nil {
		fail(w, 401, ErrForbidden)
		return
	}
	t := secure.Token()
	s.mu.Lock()
	for k, v := range s.admins {
		if time.Now().After(v.expires) {
			delete(s.admins, k)
		}
	}
	s.admins[secure.Hash(t)] = session{time.Now().Add(8 * time.Hour)}
	s.mu.Unlock()
	JSON(w, 200, map[string]string{"token": t})
}
func (s *Server) adminAccounts(w http.ResponseWriter, r *http.Request) {
	if !s.admin(r) {
		fail(w, 401, ErrForbidden)
		return
	}
	// Explicit allowlist: never serialize user routing policy to the admin API.
	type accountSummary struct {
		ID      string    `json:"id"`
		Login   string    `json:"login"`
		Status  string    `json:"status"`
		Created time.Time `json:"created"`
	}
	accounts := []accountSummary{}
	devices := []model.Device{}
	s.Store.View(func(st store.State) error {
		for _, a := range st.Accounts {
			accounts = append(accounts, accountSummary{a.ID, a.Login, a.Status, a.Created})
		}
		for _, d := range st.Devices {
			devices = append(devices, d.Device)
		}
		return nil
	})
	JSON(w, 200, map[string]any{"accounts": accounts, "devices": devices})
}
func (s *Server) adminAccount(w http.ResponseWriter, r *http.Request) {
	if !s.admin(r) {
		fail(w, 401, ErrForbidden)
		return
	}
	var c struct {
		ID     string `json:"id"`
		Status string `json:"status"`
	}
	if !body(w, r, &c) {
		return
	}
	if c.Status != "active" && c.Status != "blocked" && c.Status != "rejected" {
		fail(w, 400, errors.New("неверный статус"))
		return
	}
	e := s.mutation(func(st *store.State) error {
		a, ok := st.Accounts[c.ID]
		if !ok {
			return errors.New("аккаунт не найден")
		}
		a.Status = c.Status
		a.Revision++
		st.Accounts[a.ID] = a
		if c.Status != "active" {
			for k, p := range st.Pairs {
				if p.AccountID == a.ID {
					delete(st.Pairs, k)
				}
			}
		}
		return nil
	})
	if e != nil {
		fail(w, 503, e)
		return
	}
	JSON(w, 200, map[string]bool{"ok": true})
}
func (s *Server) syncState(w http.ResponseWriter, r *http.Request) {
	d, a, e := s.device(r)
	if e != nil {
		fail(w, 401, e)
		return
	}
	requests := []model.Request{}
	dismissed := []string{}
	devices := []model.Device{}
	s.Store.View(func(st store.State) error {
		for _, v := range st.Requests {
			if v.AccountID == a.ID && v.Dismissed {
				dismissed = append(dismissed, v.Target)
			}
			if v.AccountID == a.ID && !v.Dismissed && !policy.Approved(a.Rules, v.Target) {
				at, failed := v.FailedDevices[d.ID]
				v.DirectFailed = failed && time.Since(at) < 30*time.Minute
				v.FailedDevices = nil
				requests = append(requests, v)
			}
		}
		for _, v := range st.Devices {
			if v.AccountID == a.ID {
				devices = append(devices, v.Device)
			}
		}
		return nil
	})
	sort.Slice(requests, func(i, j int) bool {
		if requests[i].FirstSeen.Equal(requests[j].FirstSeen) {
			return requests[i].Target < requests[j].Target
		}
		return requests[i].FirstSeen.Before(requests[j].FirstSeen)
	})
	sort.Slice(devices, func(i, j int) bool {
		if devices[i].Created.Equal(devices[j].Created) {
			return devices[i].ID < devices[j].ID
		}
		return devices[i].Created.Before(devices[j].Created)
	})
	sort.Strings(dismissed)
	visible := requests[:0]
	for _, request := range requests {
		if !policy.Approved(dismissed, request.Target) {
			visible = append(visible, request)
		}
	}
	JSON(w, 200, map[string]any{"profile": s.profile(d, a, ""), "requests": visible, "dismissed": dismissed, "devices": devices})
}
func (s *Server) discover(w http.ResponseWriter, r *http.Request) {
	d, a, e := s.device(r)
	if e != nil {
		fail(w, 401, e)
		return
	}
	var input struct {
		Targets  []string `json:"targets"`
		Failed   []string `json:"failed_targets"`
		Resolved []string `json:"resolved_targets"`
	}
	if !body(w, r, &input) {
		return
	}
	if len(input.Targets)+len(input.Failed) > 100 || len(input.Resolved) > 100 {
		fail(w, 400, errors.New("слишком много адресов"))
		return
	}
	targets, e := policy.Clean(append(append([]string{}, input.Targets...), input.Failed...))
	if e != nil {
		fail(w, 400, e)
		return
	}
	failed, e := policy.Clean(input.Failed)
	if e != nil {
		fail(w, 400, e)
		return
	}
	resolved, e := policy.Clean(input.Resolved)
	if e != nil {
		fail(w, 400, e)
		return
	}
	failures := map[string]bool{}
	for _, target := range failed {
		failures[target] = true
	}
	e = s.Store.Update(func(st *store.State) error {
		if !stillAuthorized(st, d) {
			return ErrForbidden
		}
		count := 0
		dismissed := []string{}
		for _, q := range st.Requests {
			if q.AccountID == a.ID {
				if q.Dismissed {
					dismissed = append(dismissed, q.Target)
				} else {
					count++
				}
			}
		}
		for _, target := range resolved {
			key := a.ID + ":" + target
			if q, ok := st.Requests[key]; ok {
				delete(q.FailedDevices, d.ID)
				q.DirectFailed = len(q.FailedDevices) > 0
				st.Requests[key] = q
			}
		}
		for _, target := range targets {
			if policy.Approved(st.Accounts[a.ID].Rules, target) || policy.Approved(dismissed, target) {
				continue
			}
			key := a.ID + ":" + target
			q, ok := st.Requests[key]
			if !ok {
				if count >= maxDiscoveryRequests && failures[target] {
					oldest := ""
					var at time.Time
					for candidate, old := range st.Requests {
						if old.AccountID != a.ID || old.Dismissed {
							continue
						}
						active := false
						for id, seen := range old.FailedDevices {
							device := st.Devices[id]
							if time.Since(seen) < 30*time.Minute && !device.Revoked && time.Now().Before(device.Expires) {
								active = true
								break
							}
						}
						if !active && (oldest == "" || old.LastSeen.Before(at)) {
							oldest = candidate
							at = old.LastSeen
						}
					}
					if oldest != "" {
						delete(st.Requests, oldest)
						count--
					}
				}
				if count >= maxDiscoveryRequests {
					continue
				}
				count++
				q = model.Request{AccountID: a.ID, Target: target, FirstSeen: time.Now()}
			}
			q.Count++
			q.LastSeen = time.Now()
			if failures[target] {
				if q.FailedDevices == nil {
					q.FailedDevices = map[string]time.Time{}
				}
				for id, at := range q.FailedDevices {
					device := st.Devices[id]
					if time.Since(at) >= 30*time.Minute || device.Revoked || !time.Now().Before(device.Expires) {
						delete(q.FailedDevices, id)
					}
				}
				q.FailedDevices[d.ID] = time.Now()
				q.DirectFailed = true
			}
			st.Requests[key] = q
		}
		return nil
	})
	if e != nil {
		fail(w, 500, e)
		return
	}
	JSON(w, 200, map[string]bool{"ok": true})
}
func (s *Server) rules(w http.ResponseWriter, r *http.Request) {
	d, a, e := s.device(r)
	if e != nil {
		fail(w, 401, e)
		return
	}
	var c struct {
		Target   string `json:"target"`
		Action   string `json:"action"`
		Revision uint64 `json:"revision"`
	}
	if !body(w, r, &c) {
		return
	}
	target, e := policy.Normalize(c.Target)
	if e != nil {
		fail(w, 400, e)
		return
	}
	if c.Action != "approve" && c.Action != "remove" {
		fail(w, 400, errors.New("неверное действие"))
		return
	}
	if ip, e := netip.ParseAddr(target); c.Action == "approve" && e == nil && !policy.Public(ip) {
		fail(w, 400, errors.New("VPN-сервер не предоставляет доступ к внутренним и служебным IP"))
		return
	}
	e = s.mutation(func(st *store.State) error {
		if !stillAuthorized(st, d) {
			return ErrForbidden
		}
		v := st.Accounts[a.ID]
		if v.Status != "active" {
			return ErrForbidden
		}
		if v.Revision != c.Revision {
			return errors.New("список изменился на другом устройстве; обновите его")
		}
		if c.Action == "approve" {
			if len(v.Rules) >= 1000 {
				return errors.New("лимит разрешений")
			}
			v.Rules = append(v.Rules, target)
			v.Rules, _ = policy.Clean(v.Rules)
		} else {
			out := []string{}
			for _, rule := range v.Rules {
				if rule != target {
					out = append(out, rule)
				}
			}
			v.Rules = out
		}
		v.Revision++
		st.Accounts[a.ID] = v
		return nil
	})
	if e != nil {
		fail(w, 409, e)
		return
	}
	s.syncState(w, r)
}
func (s *Server) dismiss(w http.ResponseWriter, r *http.Request) {
	d, a, e := s.device(r)
	if e != nil {
		fail(w, 401, e)
		return
	}
	var c struct {
		Target string `json:"target"`
	}
	if !body(w, r, &c) {
		return
	}
	c.Target, e = policy.Normalize(c.Target)
	if e != nil {
		fail(w, 400, e)
		return
	}
	e = s.Store.Update(func(st *store.State) error {
		if !stillAuthorized(st, d) {
			return ErrForbidden
		}
		k := a.ID + ":" + c.Target
		// A dismissal is a saved user choice, not another observation. A full
		// discovery queue must not prevent dismissing a local or grouped target.
		choices := 0
		for _, request := range st.Requests {
			if request.AccountID != a.ID || !request.Dismissed {
				continue
			}
			if policy.Matches(request.Target, c.Target) {
				return nil // An existing parent choice already covers this target.
			}
			if !policy.Matches(c.Target, request.Target) {
				choices++
			}
		}
		if choices >= maxDismissedTargets {
			return errDismissedLimit
		}
		v, ok := st.Requests[k]
		if !ok {
			v = model.Request{AccountID: a.ID, Target: c.Target, FirstSeen: time.Now(), LastSeen: time.Now()}
		}
		// Compact covered subdomains without discarding unrelated observations
		// or previous choices. Existing persisted dismissals need no migration.
		for key, request := range st.Requests {
			if request.AccountID == a.ID && policy.Matches(c.Target, request.Target) {
				delete(st.Requests, key)
			}
		}
		v.Dismissed = true
		v.DirectFailed = false
		v.FailedDevices = nil
		st.Requests[k] = v
		return nil
	})
	if e != nil {
		status := http.StatusInternalServerError
		if errors.Is(e, errDismissedLimit) {
			status = http.StatusConflict
		} else if errors.Is(e, ErrForbidden) {
			status = http.StatusForbidden
		}
		fail(w, status, e)
		return
	}
	JSON(w, 200, map[string]bool{"ok": true})
}
func (s *Server) pair(w http.ResponseWriter, r *http.Request) {
	d, a, e := s.device(r)
	if e != nil {
		fail(w, 401, e)
		return
	}
	code := secure.Token()[:20]
	e = s.Store.Update(func(st *store.State) error {
		if !stillAuthorized(st, d) {
			return ErrForbidden
		}
		for k, p := range st.Pairs {
			if time.Now().After(p.Expires) || p.AccountID == a.ID {
				delete(st.Pairs, k)
			}
		}
		st.Pairs[secure.Hash(code)] = store.Pair{AccountID: a.ID, DeviceID: d.ID, Expires: time.Now().Add(5 * time.Minute)}
		return nil
	})
	if e != nil {
		fail(w, 500, e)
		return
	}
	JSON(w, 200, map[string]any{"code": code, "expires_in": 300})
}
func (s *Server) claim(w http.ResponseWriter, r *http.Request) {
	if s.limited(r, "pair", 10, 10*time.Minute) {
		fail(w, 429, ErrForbidden)
		return
	}
	var c struct {
		deviceChoice
		Code string `json:"code"`
	}
	if !body(w, r, &c) {
		return
	}
	out, err := s.enrollChoiceAuthorized(c.deviceChoice, secure.Hash(c.Code), func(st *store.State) (string, error) { return "", checkBootstrap(*st, r) })
	if err != nil {
		fail(w, 401, err)
		return
	}
	JSON(w, 200, out)
}
func (s *Server) revokeDevice(w http.ResponseWriter, r *http.Request, admin bool) {
	account := ""
	var caller store.Device
	if admin {
		if !s.admin(r) {
			fail(w, 401, ErrForbidden)
			return
		}
	} else {
		d, a, e := s.device(r)
		if e != nil {
			fail(w, 401, e)
			return
		}
		account = a.ID
		caller = d
	}
	var c struct {
		ID string `json:"id"`
	}
	if !body(w, r, &c) {
		return
	}
	e := s.mutation(func(st *store.State) error {
		if !admin && !stillAuthorized(st, caller) {
			return ErrForbidden
		}
		d, ok := st.Devices[c.ID]
		if !ok || (!admin && d.AccountID != account) {
			return ErrForbidden
		}
		deleteDevice(st, d)
		return nil
	})
	if e != nil {
		if errors.Is(e, ErrForbidden) {
			fail(w, 403, e)
		} else {
			fail(w, 503, e)
		}
		return
	}
	JSON(w, 200, map[string]bool{"ok": true})
}
func (s *Server) revoke(w http.ResponseWriter, r *http.Request)      { s.revokeDevice(w, r, false) }
func (s *Server) adminRevoke(w http.ResponseWriter, r *http.Request) { s.revokeDevice(w, r, true) }
func (c Config) Validate() error {
	if ip, e := netip.ParseAddr(c.PublicIP); e != nil || !policy.Public(ip) {
		return errors.New("public_ip должен быть публичным IP")
	}
	if c.Transport.Port != 443 {
		return fmt.Errorf("VPN должен слушать порт 443")
	}
	if c.Transport.Path == "" || c.Transport.Path == "/" || !strings.HasPrefix(c.Transport.Path, "/") {
		return errors.New("нужен непустой XHTTP path")
	}
	return nil
}
