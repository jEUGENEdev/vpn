package client

import (
	"encoding/json"
	"errors"
	"path/filepath"

	"github.com/jEUGENEdev/vpn/internal/secure"
)

const (
	TrafficSelective = "selective"
	TrafficAll       = "all"
)

func validTrafficMode(mode string) bool {
	return mode == "" || mode == TrafficSelective || mode == TrafficAll
}

func (c *Client) trafficModeLocked() string {
	if c.config.TrafficMode == TrafficAll {
		return TrafficAll
	}
	return TrafficSelective
}

// Mode is local to this device. Changing it must neither erase app decisions
// nor let existing/in-flight connections outlive the user's new policy.
func (c *Client) SetTrafficMode(mode string) error {
	if mode != TrafficSelective && mode != TrafficAll {
		return errors.New("неверный режим трафика")
	}
	c.change.Lock()
	defer c.change.Unlock()
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return errors.New("client stopped")
	}
	if c.powerPending {
		return errors.New("дождитесь переключения VPN")
	}
	if c.trafficModeLocked() == mode {
		return nil
	}
	next := c.config
	next.TrafficMode = mode
	raw, err := json.Marshal(next)
	if err != nil {
		return err
	}
	if err = secure.Save(filepath.Join(c.dir, "profile.json"), raw); err != nil {
		return err
	}
	c.config = next
	c.routeEpoch++
	for conn := range c.active {
		delete(c.active, conn)
		conn.Close()
	}
	clear(c.vpnFailures)
	c.vpnFailed = false
	return nil
}
