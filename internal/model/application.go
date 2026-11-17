package model

import (
	"encoding/hex"
	"strings"
	"time"
)

// ApplicationRule contains no application name, executable path or traffic.
// The OS-derived identity includes the platform and executable/signing identity.
type ApplicationRule struct {
	ID       string `json:"id"`
	Platform string `json:"platform"`
	Decision string `json:"decision"`
}

func (r ApplicationRule) Valid() bool {
	id, err := hex.DecodeString(r.ID)
	return err == nil && len(id) == 32 && r.ID == strings.ToLower(r.ID) &&
		(r.Decision == "trusted" || r.Decision == "addresses") &&
		(r.Platform == "android" || r.Platform == "windows" || r.Platform == "darwin" || r.Platform == "linux")
}

type ApplicationRuleChange struct {
	ID           string `json:"id"`
	Decision     string `json:"decision"`
	OnlyIfAbsent bool   `json:"only_if_absent,omitempty"`
}

// ApplicationInfo comes from the local operating system, never from a domain
// name, reverse DNS lookup or a server-supplied display name.
type ApplicationInfo struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Path     string `json:"path"`
	Platform string `json:"platform"`
}

type Application struct {
	ApplicationInfo
	Decision  string    `json:"decision"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
	Target    string    `json:"target"`
	// Legacy decisions have neither flag and are migrated only if absent.
	SyncPending   bool `json:"sync_pending,omitempty"`
	SyncConfirmed bool `json:"sync_confirmed,omitempty"`
}

type RequestGroup struct {
	Target    string            `json:"target"`
	FirstSeen time.Time         `json:"first_seen"`
	LastSeen  time.Time         `json:"last_seen"`
	Count     int               `json:"count"`
	Requests  []Request         `json:"requests"`
	Sources   []ApplicationInfo `json:"sources"`
	Unknown   bool              `json:"unknown_source"`
}

// RuleSources describes observed local traffic, not who created a shared rule.
type RuleSources struct {
	Sources []ApplicationInfo `json:"sources"`
	Unknown bool              `json:"unknown_source"`
}
