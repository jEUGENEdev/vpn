package main

import (
	"encoding/json"
	"errors"
	"os"

	"github.com/jEUGENEdev/vpn/internal/secure"
	"github.com/jEUGENEdev/vpn/internal/server"
)

// Update only the visibility setting, retaining keys and unknown config fields.
func setPublicAdmin(path string, enabled bool) (bool, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return false, err
	}
	var cfg server.Config
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return false, errors.New("invalid server configuration")
	}
	if err := cfg.Validate(); err != nil {
		return false, err
	}
	if cfg.PublicAdmin == enabled {
		return false, nil
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return false, errors.New("invalid server configuration")
	}
	fields["public_admin"], err = json.Marshal(enabled)
	if err != nil {
		return false, err
	}
	raw, err = json.MarshalIndent(fields, "", "  ")
	if err != nil {
		return false, err
	}
	if err := secure.Save(path, raw); err != nil {
		return false, err
	}
	return true, nil
}
