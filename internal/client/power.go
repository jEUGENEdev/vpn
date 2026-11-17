package client

import (
	"encoding/json"
	"errors"
	"path/filepath"

	"github.com/jEUGENEdev/vpn/internal/secure"
)

// ErrNetworkRestart means a fresh native service will apply the persisted mode.
// Until then the API reports a transition, never a completed off.
var ErrNetworkRestart = errors.New("network service restart required")

// NetworkController owns the OS interface, DNS and guard. Check must not change
// the network: Android's system lockdown can veto a request to turn VPN off.
type NetworkController interface {
	Check(enabled bool) error
	Apply(enabled bool) error
}

func (c *Client) SetNetworkController(controller NetworkController) {
	c.change.Lock()
	defer c.change.Unlock()
	c.power = controller
}

func (c *Client) VPNEnabled() bool { return !c.disabled() }

// SetNetworkError keeps the local control UI available if startup recovery
// fails, so the user sees the cause and can retry with a fresh native service.
func (c *Client) SetNetworkError(err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.powerError = err.Error()
}

func (c *Client) disabled() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.config.Disabled
}

// SetVPNEnabled persists intent before changing the OS, so a crash/restart
// retries the same mode. Failed cleanup is visible and retryable, not "off".
func (c *Client) SetVPNEnabled(enabled bool) error {
	c.change.Lock()
	defer c.change.Unlock()
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return errors.New("client stopped")
	}
	if c.powerPending || (c.config.Disabled == !enabled && c.powerError == "") {
		c.mu.Unlock()
		return nil
	}
	c.mu.Unlock()
	if c.power != nil {
		if err := c.power.Check(enabled); err != nil {
			return err
		}
	}
	c.mu.Lock()
	next := c.config
	next.Disabled = !enabled
	raw, err := json.Marshal(next)
	if err != nil {
		c.mu.Unlock()
		return err
	}
	if err = secure.Save(filepath.Join(c.dir, "profile.json"), raw); err != nil {
		c.mu.Unlock()
		return err
	}
	c.config = next
	c.powerPending, c.powerError = true, ""
	c.routeEpoch++
	c.ready, c.vpnFailed = false, false
	clear(c.fallbacks)
	for flow := range c.active {
		delete(c.active, flow)
		flow.Close()
	}
	c.vpn.Close()
	c.appVPN.Close()
	if c.http != nil {
		c.http.CloseIdleConnections()
	}
	c.status = "blocked"
	if c.config.Profile.Token == "" {
		c.status = "setup"
	}
	c.mu.Unlock()
	// Native callbacks close/create TUNs and update their state. The packet
	// stack and JNI callbacks also need c.mu, so do not hold it here.
	if c.power != nil {
		err = c.power.Apply(enabled)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if errors.Is(err, ErrNetworkRestart) {
		return nil
	}
	c.powerPending = false
	if err != nil {
		c.powerError = err.Error()
	}
	return err
}
