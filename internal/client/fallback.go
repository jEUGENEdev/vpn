package client

import "time"

// A failed media peer is not evidence that every other destination or app has
// lost VPN connectivity. Keep the availability fallback local to that choice.
type fallbackKey struct{ Target, AppID string }

// Caller holds c.mu. Bound memory even when an app probes many failed peers.
func (c *Client) failVPNLocked(target, appID string, now time.Time) {
	if c.fallbacks == nil {
		c.fallbacks = map[fallbackKey]time.Time{}
	}
	for key, until := range c.fallbacks {
		if !now.Before(until) {
			delete(c.fallbacks, key)
		}
	}
	key := fallbackKey{target, appID}
	if _, exists := c.fallbacks[key]; !exists && len(c.fallbacks) >= 1000 {
		var oldest fallbackKey
		var at time.Time
		for candidate, until := range c.fallbacks {
			if at.IsZero() || until.Before(at) {
				oldest, at = candidate, until
			}
		}
		delete(c.fallbacks, oldest)
	}
	c.fallbacks[key] = now.Add(30 * time.Second)
	c.vpnFailed = true
}

func (c *Client) recoverVPNLocked(target, appID string, now time.Time) bool {
	wasFailed := c.vpnFailed
	delete(c.fallbacks, fallbackKey{target, appID})
	for key, until := range c.fallbacks {
		if !now.Before(until) {
			delete(c.fallbacks, key)
		}
	}
	c.vpnFailed = len(c.fallbacks) > 0
	return wasFailed && !c.vpnFailed
}
