package client

import (
	"time"

	"github.com/jEUGENEdev/vpn/internal/policy"
)

// Failures are diagnostic only. They must never authorize direct egress,
// including for the exact endpoint that failed. Retries use the VPN again.
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
	for flow, until := range c.vpnFailures {
		if !now.Before(until) {
			delete(c.vpnFailures, flow)
		}
	}
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
	c.vpnFailures[key] = now.Add(30 * time.Second)
	c.vpnFailed = true
}

func (c *Client) recoverVPNLocked(key flowKey) {
	delete(c.vpnFailures, key)
	now := time.Now()
	for flow, until := range c.vpnFailures {
		if !now.Before(until) {
			delete(c.vpnFailures, flow)
		}
	}
	c.vpnFailed = len(c.vpnFailures) != 0
}
