package client

import (
	"net"
	"testing"
	"time"

	"github.com/jEUGENEdev/vpn/internal/model"
	"github.com/jEUGENEdev/vpn/internal/policy"
)

func TestFailedPeerDoesNotBypassOtherVPNPermissions(t *testing.T) {
	c := testTrafficClient(t)
	c.ready = true
	c.config.Profile.Rules = []string{"media.example", "other.example"}
	app := testApp("a")
	other := testApp("b")
	c.apps[app.ID] = model.Application{ApplicationInfo: app, Decision: "trusted"}
	c.config.Profile.AppUUID = "configured"
	left, right := net.Pipe()
	defer right.Close()
	c.active[left] = activeFlow{Target: "media.example", AppID: app.ID, Route: policy.VPN}
	flow := &tracked{Conn: left, c: c, source: app}
	flow.reportResponseTimeout()
	for _, tc := range []struct {
		target, app string
		route       policy.Route
	}{
		{"media.example", app.ID, policy.Direct},
		{"other.example", app.ID, policy.VPN},
		{"media.example", other.ID, policy.VPN},
		{"cdn.example", app.ID, policy.AppVPN},
		{"unapproved.example", other.ID, policy.Direct},
	} {
		if got := c.routeLocked(tc.target, tc.app); got != tc.route {
			t.Errorf("%s / %s: got %v want %v", tc.target, tc.app, got, tc.route)
		}
	}
}

func TestRecoveryIsScopedAndFallbackMemoryIsBounded(t *testing.T) {
	c := testTrafficClient(t)
	c.ready = true
	c.config.Profile.Rules = []string{"first.example", "second.example"}
	now := time.Now()
	c.failVPNLocked("first.example", "", now)
	c.failVPNLocked("second.example", "", now)
	if c.recoverVPNLocked("first.example", "", now) || !c.vpnFailed {
		t.Fatal("one reply concealed another failing peer")
	}
	if c.routeLocked("first.example", "") != policy.VPN || c.routeLocked("second.example", "") != policy.Direct {
		t.Fatal("recovery changed unrelated route")
	}
	if !c.recoverVPNLocked("second.example", "", now) || c.vpnFailed {
		t.Fatal("recovery was not reported")
	}
	for i := 0; i < 1100; i++ {
		c.failVPNLocked(time.Unix(int64(i), 0).String(), "", now)
	}
	if len(c.fallbacks) > 1000 {
		t.Fatal("unbounded failed peer cache")
	}
	if !c.recoverVPNLocked("", "", now.Add(time.Minute)) || len(c.fallbacks) != 0 {
		t.Fatal("expired fallback entries retained")
	}
}
