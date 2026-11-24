package desktopcontrol

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/jEUGENEdev/vpn/internal/secure"
)

const settingsLifetime = 12 * time.Hour
const settingsPrefix = "/local/control/settings/"

// The service keeps this installation's signing key across network restarts.
// A settings grant lives only in the desktop main process and expires even if copied.
type SettingsKey struct{ secret [32]byte }

func loadSettingsKey(private string) (*SettingsKey, error) {
	path := filepath.Join(private, "settings.key")
	data, err := secure.ReadPrivateFile(path)
	key := new(SettingsKey)
	if os.IsNotExist(err) {
		rand.Read(key.secret[:])
		return key, secure.Save(path, key.secret[:])
	}
	if err != nil {
		return nil, err
	}
	if len(data) != len(key.secret) {
		return nil, errors.New("invalid desktop settings key")
	}
	copy(key.secret[:], data)
	return key, nil
}

func (key *SettingsKey) issue(now time.Time) map[string]any {
	expires := now.Add(settingsLifetime).Unix()
	var payload [8 + 32]byte
	binary.BigEndian.PutUint64(payload[:8], uint64(expires))
	rand.Read(payload[8:])
	mac := hmac.New(sha256.New, key.secret[:])
	mac.Write(payload[:])
	return map[string]any{"token": base64.RawURLEncoding.EncodeToString(mac.Sum(payload[:])), "expires_at": expires}
}

func (key *SettingsKey) accepts(token string, now time.Time) bool {
	const payloadSize = 8 + 32
	if key == nil || len(token) != base64.RawURLEncoding.EncodedLen(payloadSize+sha256.Size) {
		return false
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(token)
	if err != nil || len(raw) != payloadSize+sha256.Size {
		return false
	}
	mac := hmac.New(sha256.New, key.secret[:])
	mac.Write(raw[:payloadSize])
	return hmac.Equal(raw[payloadSize:], mac.Sum(nil)) && int64(binary.BigEndian.Uint64(raw[:8])) > now.Unix()
}

// Only routing preferences can use the session. Identity, device and account
// operations still use individual reviews over the administrative channel.
func (b *Bridge) settings(w http.ResponseWriter, r *http.Request) {
	bearer, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok || !b.settingsKey.accepts(bearer, b.now()) {
		fail(w, http.StatusUnauthorized, "Сеанс управления настройками завершён. Повторите изменение.")
		return
	}
	if r.Method != http.MethodPost {
		fail(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	action := strings.TrimPrefix(r.URL.Path, settingsPrefix)
	switch action {
	case "rules", "dismiss", "applications", "applications/add", "vpn", "traffic-mode":
		req := r.Clone(r.Context())
		req.URL.Path = "/local/" + action
		req.Header.Set("Authorization", "Bearer "+b.controlToken)
		b.execute.ServeHTTP(w, req)
	default:
		fail(w, http.StatusForbidden, "Сеанс не разрешает эту команду")
	}
}
