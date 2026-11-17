package client

import (
	"encoding/json"
	"errors"
	"path/filepath"

	"github.com/jEUGENEdev/vpn/internal/secure"
)

func (c *Client) disabled() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.config.Disabled
}

// SetVPNEnabled changes only this device's routing. The TUN and OS guard stay
// alive so cached fake DNS addresses keep working, including Android lockdown.
// Explicit off means direct traffic; an enabled VPN failure still fails closed.
func (c *Client) SetVPNEnabled(enabled bool) error {
	c.change.Lock()
	defer c.change.Unlock()
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return errors.New("client stopped")
	}
	if c.config.Disabled == !enabled {
		return nil
	}
	next := c.config
	next.Disabled = !enabled
	raw, err := json.Marshal(next)
	if err != nil {
		return err
	}
	if err = secure.Save(filepath.Join(c.dir, "profile.json"), raw); err != nil {
		return err
	}
	c.config = next
	c.routeEpoch++
	c.ready, c.vpnFailed = false, false
	for flow := range c.active {
		delete(c.active, flow)
		flow.Close()
	}
	c.vpn.Close()
	c.appVPN.Close()
	if enabled {
		if c.config.Profile.Token == "" {
			c.status = "setup"
		} else {
			c.status = "blocked"
		}
	} else {
		c.status = "disabled"
	}
	return nil
}
