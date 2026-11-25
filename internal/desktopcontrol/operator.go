package desktopcontrol

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/jEUGENEdev/vpn/internal/secure"
)

// Only the installer-designated user may request a native review. Knowing
// their prompt token cannot accept it or execute a command. The service
// supplies the immutable summary and receives the OS dialog result itself.
func (b *Bridge) Operator(token string, prompt func(context.Context, string) (bool, error)) http.Handler {
	showing := make(chan struct{}, 1)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !authorized(r, token) || prompt == nil {
			fail(w, 403, "Управление не поручено этому пользователю")
			return
		}
		if r.Method != http.MethodPost {
			fail(w, 405, "method not allowed")
			return
		}
		var proof struct{ ID, Receipt string }
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 512)).Decode(&proof); err != nil {
			fail(w, 400, "Неверная квитанция")
			return
		}
		b.mu.Lock()
		b.pruneLocked()
		t := b.pending[proof.ID]
		if t == nil || t.Used || !secure.Equal(t.Receipt, proof.Receipt) {
			b.mu.Unlock()
			fail(w, 409, "Запрос истёк или уже обработан")
			return
		}
		select {
		case showing <- struct{}{}:
			defer func() { <-showing }()
		default:
			b.mu.Unlock()
			fail(w, 409, "Дождитесь открытого подтверждения")
			return
		}
		summary, digest := t.Summary, t.Digest
		b.mu.Unlock()
		ctx, cancel := context.WithTimeout(r.Context(), 90*time.Second)
		defer cancel()
		// The usual 30s HTTP write deadline is for API calls, not human input.
		if err := http.NewResponseController(w).SetWriteDeadline(time.Now().Add(115 * time.Second)); err != nil && !errors.Is(err, http.ErrNotSupported) {
			fail(w, 503, "Не удалось открыть подтверждение")
			return
		}
		allow, err := prompt(ctx, summary)
		if err != nil || ctx.Err() != nil {
			fail(w, 503, "Подтверждение пользователя недоступно")
			return
		}
		path := "/cancel"
		if allow {
			path = "/commit"
		}
		body, _ := json.Marshal(map[string]string{"digest": digest})
		req, _ := http.NewRequestWithContext(r.Context(), http.MethodPost, path, bytes.NewReader(body))
		query := req.URL.Query()
		query.Set("id", proof.ID)
		req.URL.RawQuery = query.Encode()
		req.Header.Set("Authorization", "Bearer "+b.controlToken)
		b.Privileged().ServeHTTP(w, req)
	})
}
