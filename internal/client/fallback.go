package client

import (
	"sort"
	"time"

	"github.com/jEUGENEdev/vpn/internal/model"
	"github.com/jEUGENEdev/vpn/internal/policy"
)

// Failures describe endpoints, never a change in the user's routing policy.
type flowKey struct {
	Target, AppID, Network string
	Port                   uint16
}

func (f activeFlow) key() flowKey {
	return flowKey{Target: f.Target, AppID: f.AppID, Network: f.Network, Port: f.Port}
}

// Caller holds c.mu (at least for reading).
func (c *Client) routeFlowLocked(key flowKey) policy.Route {
	return c.routeLocked(key.Target, key.AppID)
}

// Caller holds c.mu for writing. Keep memory bounded even during a long outage.
func (c *Client) failVPNLocked(key flowKey) {
	if c.vpnFailures == nil {
		c.vpnFailures = map[flowKey]time.Time{}
	}
	now := time.Now()
	if _, exists := c.vpnFailures[key]; !exists && len(c.vpnFailures) >= 1000 {
		var oldest flowKey
		var at time.Time
		for flow, until := range c.vpnFailures {
			if at.IsZero() || until.Before(at) {
				oldest, at = flow, until
			}
		}
		delete(c.vpnFailures, oldest)
	}
	c.vpnFailures[key] = now
	c.vpnFailed = true
}

func (c *Client) recoverVPNLocked(key flowKey) {
	delete(c.vpnFailures, key)
	// An unrelated response or elapsed cooldown cannot prove recovery of this
	// endpoint. Keep its last failure visible until this route receives data.
	c.vpnFailed = len(c.vpnFailures) != 0
}

type vpnIssue struct {
	Target  string                `json:"target"`
	Network string                `json:"network"`
	Port    uint16                `json:"port"`
	At      time.Time             `json:"at"`
	Source  model.ApplicationInfo `json:"source"`
}

// Caller holds c.mu. Expose bounded diagnostics without credentials or payloads.
func (c *Client) vpnIssuesLocked() []vpnIssue {
	issues := make([]vpnIssue, 0, len(c.vpnFailures))
	for key, at := range c.vpnFailures {
		issues = append(issues, vpnIssue{Target: key.Target, Network: key.Network, Port: key.Port, At: at, Source: c.apps[key.AppID].ApplicationInfo})
	}
	sort.Slice(issues, func(i, j int) bool {
		if issues[i].Target != issues[j].Target {
			return issues[i].Target < issues[j].Target
		}
		if issues[i].Source.ID != issues[j].Source.ID {
			return issues[i].Source.ID < issues[j].Source.ID
		}
		if issues[i].Network != issues[j].Network {
			return issues[i].Network < issues[j].Network
		}
		return issues[i].Port < issues[j].Port
	})
	return issues
}
