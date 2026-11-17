package client

import (
	"time"

	"github.com/jEUGENEdev/vpn/internal/policy"
)

// A failed UDP endpoint must not switch TCP, other media hosts or another
// application's traffic to direct. Only this exact route gets a short retry.
type flowKey struct {
	Target, AppID, Network string
	Port                   uint16
}

func (f activeFlow) key() flowKey {
	return flowKey{Target: f.Target, AppID: f.AppID, Network: f.Network, Port: f.Port}
}

// Caller holds c.mu (at least for reading).
func (c *Client) routeFlowLocked(key flowKey) policy.Route {
	route := c.routeLocked(key.Target, key.AppID)
	if route != policy.Block && time.Now().Before(c.vpnFailures[key]) {
		return policy.Direct
	}
	return route
}

// Caller holds c.mu for writing. Keep memory bounded even during a long outage.
func (c *Client) failVPNLocked(key flowKey) {
	if c.vpnFailures == nil {
		c.vpnFailures = map[flowKey]time.Time{}
	}
	now := time.Now()
	for flow, until := range c.vpnFailures {
		if !now.Before(until) {
			delete(c.vpnFailures, flow)
		}
	}
	if len(c.vpnFailures) >= 1000 {
		var oldest flowKey
		var at time.Time
		for flow, until := range c.vpnFailures {
			if at.IsZero() || until.Before(at) {
				oldest, at = flow, until
			}
		}
		delete(c.vpnFailures, oldest)
	}
	c.vpnFailures[key] = now.Add(30 * time.Second)
	c.vpnFailed = true
}

func (c *Client) recoverVPNLocked(key flowKey) {
	delete(c.vpnFailures, key)
	c.vpnFailed = len(c.vpnFailures) != 0
}
