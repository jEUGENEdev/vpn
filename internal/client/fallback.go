package client

import (
	"time"

	"github.com/jEUGENEdev/vpn/internal/policy"
)

// A failed destination is not evidence that every VPN destination is down.
// Include protocol, port and application so a silent UDP media socket cannot
// switch unrelated HTTPS connections (or another app) to direct routing.
type fallbackKey struct {
	Target, AppID, Network string
	Port                   uint16
}

func (f activeFlow) fallbackKey() fallbackKey {
	return fallbackKey{f.Target, f.AppID, f.Network, f.Port}
}

func (c *Client) routeFlowLocked(target, appID, network string, port uint16) policy.Route {
	route := c.routeLocked(target, appID)
	if (route == policy.VPN || route == policy.AppVPN) && time.Now().Before(c.fallbacks[fallbackKey{target, appID, network, port}]) {
		return policy.Direct
	}
	return route
}

func (c *Client) failedVPNLocked(flow activeFlow) {
	if c.fallbacks == nil {
		c.fallbacks = make(map[fallbackKey]time.Time)
	}
	now := time.Now()
	// Bound memory while retaining a cooldown for each failing destination.
	if len(c.fallbacks) >= 1024 {
		for key, until := range c.fallbacks {
			if !now.Before(until) {
				delete(c.fallbacks, key)
			}
		}
	}
	key := flow.fallbackKey()
	if _, exists := c.fallbacks[key]; !exists && len(c.fallbacks) >= 1024 {
		var oldest fallbackKey
		var earliest time.Time
		for candidate, until := range c.fallbacks {
			if earliest.IsZero() || until.Before(earliest) {
				oldest, earliest = candidate, until
			}
		}
		delete(c.fallbacks, oldest)
	}
	c.fallbacks[key] = now.Add(30 * time.Second)
	c.vpnFailed = len(c.fallbacks) > 0
}

func (c *Client) recoveredVPNLocked(flow activeFlow) bool {
	key := flow.fallbackKey()
	_, failed := c.fallbacks[key]
	delete(c.fallbacks, key)
	c.vpnFailed = len(c.fallbacks) > 0
	return failed
}
