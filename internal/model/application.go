package model

import "time"

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
