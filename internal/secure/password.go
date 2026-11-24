package secure

import (
	"errors"
	"golang.org/x/crypto/bcrypt"
	"strings"
)

// AdminHash accepts a bcrypt hash or migrates a validated legacy plaintext.
// A malformed hash is never reinterpreted as a plaintext password.
func AdminHash(value string) ([]byte, error) {
	if strings.HasPrefix(value, "$2") {
		cost, err := bcrypt.Cost([]byte(value))
		if err != nil || cost < bcrypt.DefaultCost || cost > 16 {
			return nil, errors.New("invalid admin bcrypt hash")
		}
		return []byte(value), nil
	}
	if len(value) < 16 || len(value) > 72 || value != strings.TrimSpace(value) || strings.ContainsAny(value, "\r\n\x00") {
		return nil, errors.New("admin password must be 16–72 UTF-8 bytes without surrounding whitespace")
	}
	return bcrypt.GenerateFromPassword([]byte(value), bcrypt.DefaultCost)
}
