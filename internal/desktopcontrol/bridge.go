// Package desktopcontrol separates public desktop status from privileged policy changes.
package desktopcontrol

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"time"

	"github.com/jEUGENEdev/vpn/internal/secure"
)

const MaxBody = 32768
const lifetime = 3 * time.Minute
const maxPending = 16

var actions = map[string]string{
	"settings-session": "Разрешить управление настройками VPN",
	"bootstrap":        "Изменить сервер VPN", "login": "Войти в аккаунт", "register": "Создать аккаунт", "pair/claim": "Привязать устройство",
	"rules": "Изменить разрешение адреса", "dismiss": "Изменить прямой маршрут", "pair": "Создать код привязки", "revoke": "Отозвать устройство",
	"applications": "Изменить разрешение приложения", "vpn": "Переключить VPN", "traffic-mode": "Изменить режим трафика", "access-key/rotate": "Заменить ключ аккаунта",
}

type proposal struct {
	Action string          `json:"action"`
	Data   json.RawMessage `json:"data"`
}
type ticket struct {
	proposal
	Receipt, Summary, Digest string
	Created                  time.Time
	Used                     bool
	Status                   int
	Result                   json.RawMessage
}

// Bridge holds immutable, short-lived proposals. Possession of a status token,
// proposal ID, or result receipt never authorizes execution.
type Bridge struct {
	mu                      sync.Mutex
	pending                 map[string]*ticket
	readToken, controlToken string
	settingsKey             *SettingsKey
	execute                 http.Handler
	describe                func(string, json.RawMessage) (string, error)
	now                     func() time.Time
}

func New(readToken, controlToken string, settingsKey *SettingsKey, execute http.Handler, describe func(string, json.RawMessage) (string, error)) *Bridge {
	return &Bridge{pending: make(map[string]*ticket), readToken: readToken, controlToken: controlToken, settingsKey: settingsKey, execute: execute, describe: describe, now: time.Now}
}
func reply(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(value)
}
func fail(w http.ResponseWriter, status int, message string) {
	reply(w, status, map[string]string{"error": message})
}
func authorized(r *http.Request, token string) bool {
	return token != "" && secure.Equal(r.Header.Get("Authorization"), "Bearer "+token)
}
func (b *Bridge) pruneLocked() {
	for id, t := range b.pending {
		if b.now().Sub(t.Created) >= lifetime {
			delete(b.pending, id)
		}
	}
}

// Public serves status and proposals. Only a separate, approved settings grant
// can execute a routing change through this listener.
func (b *Bridge) Public(readOnly http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, settingsPrefix) {
			b.settings(w, r)
			return
		}
		if r.URL.Path == "/local/control/request" {
			if !authorized(r, b.readToken) {
				fail(w, 401, "unauthorized")
				return
			}
			if r.Method != "POST" {
				fail(w, 405, "method not allowed")
				return
			}
			var p proposal
			raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, MaxBody))
			if err != nil || json.Unmarshal(raw, &p) != nil || actions[p.Action] == "" || len(p.Data) == 0 {
				fail(w, 400, "неверная команда")
				return
			}
			var data map[string]any
			if json.Unmarshal(p.Data, &data) != nil || data == nil {
				fail(w, 400, "неверные параметры")
				return
			}
			summary, err := b.describe(p.Action, p.Data)
			if err != nil {
				fail(w, 400, "невозможно безопасно показать команду")
				return
			}
			hash := sha256.Sum256(append(append([]byte(p.Action+"\n"), p.Data...), []byte("\n"+summary)...))
			b.mu.Lock()
			defer b.mu.Unlock()
			b.pruneLocked()
			if len(b.pending) >= maxPending {
				fail(w, 429, "слишком много ожидающих подтверждений")
				return
			}
			id, receipt := secure.Token(), secure.Token()
			b.pending[id] = &ticket{proposal: p, Receipt: receipt, Summary: summary, Digest: hex.EncodeToString(hash[:]), Created: b.now()}
			reply(w, 201, map[string]string{"id": id, "receipt": receipt})
			return
		}
		if strings.HasPrefix(r.URL.Path, "/local/control/result/") {
			if r.Method != "GET" {
				fail(w, 405, "method not allowed")
				return
			}
			id := strings.TrimPrefix(r.URL.Path, "/local/control/result/")
			b.mu.Lock()
			defer b.mu.Unlock()
			b.pruneLocked()
			t := b.pending[id]
			if t == nil || !authorized(r, t.Receipt) {
				fail(w, 404, "подтверждение истекло")
				return
			}
			if t.Result == nil {
				reply(w, 202, map[string]bool{"pending": true})
				return
			}
			if t.Action == "settings-session" {
				delete(b.pending, id)
			}
			reply(w, 200, map[string]any{"status": t.Status, "body": t.Result})
			return
		}
		readOnly.ServeHTTP(w, r)
	})
}

// Privileged is reachable only over the separately pinned TLS channel. Its
// credential is stored in a service/admin-only directory and never reaches UI.
func (b *Bridge) Privileged() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !authorized(r, b.controlToken) {
			fail(w, 401, "unauthorized")
			return
		}
		id := r.URL.Query().Get("id")
		b.mu.Lock()
		b.pruneLocked()
		t := b.pending[id]
		if t == nil || t.Used {
			b.mu.Unlock()
			fail(w, 409, "команда истекла или уже обработана")
			return
		}
		if r.Method == "GET" && r.URL.Path == "/review" {
			summary, digest := t.Summary, t.Digest
			b.mu.Unlock()
			reply(w, 200, map[string]string{"summary": summary, "digest": digest})
			return
		}
		if r.Method != "POST" || (r.URL.Path != "/commit" && r.URL.Path != "/cancel") {
			b.mu.Unlock()
			fail(w, 404, "not found")
			return
		}
		var data struct {
			Digest string `json:"digest"`
		}
		raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1024))
		if err != nil || json.Unmarshal(raw, &data) != nil || !secure.Equal(data.Digest, t.Digest) {
			b.mu.Unlock()
			fail(w, 409, "команда изменилась")
			return
		}
		t.Used = true
		if r.URL.Path == "/cancel" {
			t.Status = 403
			t.Result = json.RawMessage(`{"error":"Изменение отменено пользователем"}`)
			b.mu.Unlock()
			reply(w, 200, map[string]bool{"ok": true})
			return
		}
		if t.Action == "settings-session" {
			// Only the requester holding the receipt gets the grant. The
			// elevated helper receives the same acknowledgement as for a change.
			if b.settingsKey == nil {
				t.Status = http.StatusServiceUnavailable
				t.Result = json.RawMessage(`{"error":"Сеанс управления недоступен"}`)
			} else {
				t.Status = http.StatusOK
				t.Result, _ = json.Marshal(b.settingsKey.issue(b.now()))
			}
			b.mu.Unlock()
			reply(w, 200, map[string]bool{"ok": true})
			return
		}
		// Consume before any side effect; concurrent approval/replay cannot execute twice.
		b.mu.Unlock()
		req, _ := http.NewRequestWithContext(r.Context(), "POST", "http://localhost/local/"+t.Action, bytes.NewReader(t.Data))
		req.Header.Set("Authorization", "Bearer "+b.controlToken)
		req.Header.Set("Content-Type", "application/json")
		out := httptest.NewRecorder()
		b.execute.ServeHTTP(out, req)
		result := out.Body.Bytes()
		if !json.Valid(result) {
			result = []byte(`{"error":"Неверный ответ службы"}`)
		}
		b.mu.Lock()
		t.Status = out.Code
		t.Result = append([]byte(nil), result...)
		b.mu.Unlock()
		// Never reveal registration keys/results to the helper or its command output.
		reply(w, 200, map[string]bool{"ok": true})
	})
}

func ActionTitle(action string) (string, error) {
	if title := actions[action]; title != "" {
		return title, nil
	}
	return "", errors.New("unknown action")
}
