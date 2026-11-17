package client

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"unicode"

	"github.com/jEUGENEdev/vpn/internal/policy"
	"github.com/jEUGENEdev/vpn/internal/secure"
)

// DeviceIdentity comes from the native service, never from a browser user agent.
type DeviceIdentity struct {
	Name     string `json:"name"`
	Platform string `json:"platform"`
}

// Call with change and mu held. Account rules remain fail-closed across restart;
// deleted/expired credentials do not remain on the local disk.
func (c *Client) forgetAccessLocked() error {
	c.ready = false
	c.routeEpoch++
	clear(c.vpnFailures)
	c.vpnFailed = false
	c.status = "auth_required"
	c.config.Profile.Token = ""
	c.config.Profile.UUID = ""
	c.config.Profile.AppUUID = ""
	c.config.Profile.Status = "auth_required"
	c.devices = nil
	for flow, info := range c.active {
		if info.Route != policy.Direct {
			delete(c.active, flow)
			flow.Close()
		}
	}
	c.vpn.Close()
	c.appVPN.Close()
	raw, err := json.Marshal(c.config)
	if err != nil {
		return err
	}
	return secure.Save(filepath.Join(c.dir, "profile.json"), raw)
}

func cleanDeviceName(name string) string {
	name = strings.TrimSpace(name)
	switch strings.ToLower(name) {
	case "", "localhost", "localhost.localdomain", "unknown", "android":
		return ""
	}
	for _, r := range name {
		if unicode.IsControl(r) {
			return ""
		}
	}
	// The server limit is bytes; never split a UTF-8 code point.
	for len(name) > 80 {
		name = string([]rune(name)[:len([]rune(name))-1])
	}
	return name
}

func nativeDeviceIdentity() DeviceIdentity {
	name, _ := os.Hostname()
	if runtime.GOOS == "android" {
		name = ""
	} // Android supplies Build.MODEL below.
	return DeviceIdentity{Name: cleanDeviceName(name), Platform: runtime.GOOS}
}

// SetDeviceName is used by the native Android bridge before exposing the API.
func (c *Client) SetDeviceName(name string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.identity.Name = cleanDeviceName(name)
}

func (c *Client) authDeviceData(data any) (map[string]any, error) {
	fields, ok := data.(map[string]any)
	if !ok {
		return nil, errors.New("некорректное устройство")
	}
	result := make(map[string]any, len(fields)+3)
	for k, v := range fields {
		result[k] = v
	}
	c.mu.RLock()
	identity, current := c.identity, c.config.Profile.DeviceID
	c.mu.RUnlock()
	result["name"], result["platform"] = identity.Name, identity.Platform
	if identity.Name != "" {
		// A known installation reauthenticates its own record, never an arbitrary
		// device selected by renderer input. Names do not prove device identity.
		delete(result, "new_device")
		delete(result, "device_id")
		if current != "" {
			result["device_id"] = current
		}
	} else if _, selected := result["device_id"]; !selected && result["new_device"] != true && current != "" {
		result["device_id"] = current
	}
	return result, nil
}
