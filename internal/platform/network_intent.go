//go:build !android

package platform

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
)

// Startup may restore direct access only after explicit persisted off. Missing
// or unreadable intent is never permission to remove an existing deny policy.
func prepareNetwork(dir string, guard func(string) error, recover func(string) error) error {
	raw, err := os.ReadFile(filepath.Join(dir, "profile.json"))
	var intent struct {
		Disabled bool `json:"vpn_disabled"`
	}
	if err == nil {
		err = json.Unmarshal(raw, &intent)
	}
	if err == nil && intent.Disabled {
		return recover(dir)
	}
	guardErr := guard("")
	if os.IsNotExist(err) {
		err = nil
	}
	return errors.Join(err, guardErr)
}
