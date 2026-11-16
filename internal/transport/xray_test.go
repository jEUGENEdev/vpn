package transport

import (
	"github.com/jEUGENEdev/vpn/internal/model"
	"github.com/jEUGENEdev/vpn/internal/policy"
	"github.com/jEUGENEdev/vpn/internal/store"
	"net/netip"
	"testing"
	"time"
)

func TestConfigDenyByDefaultAndPerDevice(t *testing.T) {
	s := store.Empty()
	now := time.Now()
	s.Accounts["a"] = store.Account{Account: model.Account{ID: "a", Status: "active", Rules: []string{"example.com", "8.8.8.8"}}}
	s.Devices["d"] = store.Device{Device: model.Device{ID: "d", AccountID: "a", Expires: now.Add(time.Hour)}, Secret: "123"}
	c := ServerConfig(s, ServerOptions{}, now)
	out := c["outbounds"].([]obj)
	if out[0]["protocol"] != "blackhole" {
		t.Fatal("default allow")
	}
	rules := c["routing"].(obj)["rules"].([]obj)
	if len(rules) != 2 || rules[0]["user"].([]string)[0] != "d" {
		t.Fatal("not device scoped")
	}
	d := s.Devices["d"]
	d.Revoked = true
	s.Devices["d"] = d
	c = ServerConfig(s, ServerOptions{}, now)
	if len(c["routing"].(obj)["rules"].([]obj)) != 0 {
		t.Fatal("revoked device allowed")
	}
}
func TestPrivateEgressDenied(t *testing.T) {
	for _, s := range []string{"127.0.0.1", "10.0.0.1", "169.254.169.254", "100.100.100.200", "::ffff:127.0.0.1", "::1", "2002:7f00:1::", "64:ff9b::7f00:1", "198.18.0.1"} {
		if policy.Public(netip.MustParseAddr(s)) {
			t.Fatal(s)
		}
	}
	if !policy.Public(netip.MustParseAddr("1.1.1.1")) {
		t.Fatal("public rejected")
	}
}

func TestApplicationCredentialDoesNotWidenAddressCredential(t *testing.T) {
	s := store.Empty()
	now := time.Now()
	s.Accounts["a"] = store.Account{Account: model.Account{ID: "a", Status: "active", Rules: []string{"example.com"}}}
	s.Devices["d"] = store.Device{Device: model.Device{ID: "d", AccountID: "a", Expires: now.Add(time.Hour)}, Secret: "address-key", AppSecret: "app-key"}
	cfg := ServerConfig(s, ServerOptions{}, now)
	rules := cfg["routing"].(obj)["rules"].([]obj)
	if len(rules) != 2 {
		t.Fatal(rules)
	}
	for _, r := range rules {
		user := r["user"].([]string)[0]
		if user == "d" && r["domain"] == nil {
			t.Fatal("address credential became unrestricted")
		}
		if user != "d" && user != "d:apps" {
			t.Fatal("unscoped app route")
		}
	}
	device := s.Devices["d"]
	device.Revoked = true
	s.Devices["d"] = device
	if len(ServerConfig(s, ServerOptions{}, now)["routing"].(obj)["rules"].([]obj)) != 0 {
		t.Fatal("app credential survived revocation")
	}
}
