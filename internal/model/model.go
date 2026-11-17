package model

import "time"

type Account struct {
	ID           string    `json:"id"`
	Login        string    `json:"login"`
	PasswordHash string    `json:"-"`
	Status       string    `json:"status"`
	Created      time.Time `json:"created"`
	Rules        []string  `json:"rules"`
	Revision     uint64    `json:"revision"`
}
type Device struct {
	ID        string    `json:"id"`
	AccountID string    `json:"account_id"`
	Name      string    `json:"name"`
	Platform  string    `json:"platform"`
	VLESS     string    `json:"-"`
	TokenHash string    `json:"-"`
	Expires   time.Time `json:"expires"`
	Revoked   bool      `json:"revoked"`
	Created   time.Time `json:"created"`
}
type Request struct {
	DirectFailed  bool                 `json:"direct_failed,omitempty"`
	FailedDevices map[string]time.Time `json:"failed_devices,omitempty"`
	AccountID     string               `json:"account_id"`
	Target        string               `json:"target"`
	FirstSeen     time.Time            `json:"first_seen"`
	LastSeen      time.Time            `json:"last_seen"`
	Count         int                  `json:"count"`
	Dismissed     bool                 `json:"dismissed"`
	Sources       []ApplicationInfo    `json:"sources,omitempty"`
	Unknown       bool                 `json:"unknown_source,omitempty"`
}
type Profile struct {
	// nil denotes a server without application-rule sync; [] denotes support.
	ApplicationRules []ApplicationRule `json:"application_rules"`

	Login     string   `json:"login"`
	DeviceID  string   `json:"device_id"`
	AccountID string   `json:"account_id"`
	Token     string   `json:"token,omitempty"`
	Server    string   `json:"server"`
	Port      int      `json:"port"`
	UUID      string   `json:"uuid"`
	AppUUID   string   `json:"app_uuid,omitempty"`
	SNI       string   `json:"sni"`
	PublicKey string   `json:"public_key"`
	ShortID   string   `json:"short_id"`
	Path      string   `json:"path"`
	Rules     []string `json:"rules"`
	Revision  uint64   `json:"revision"`
	Status    string   `json:"status"`
}
