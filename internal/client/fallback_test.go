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
		{"media.example", app.ID, policy.VPN},
		{"other.example", app.ID, policy.VPN},
		{"media.example", other.ID, policy.VPN},
		{"cdn.example", app.ID, policy.AppVPN},
		{"unapproved.example", other.ID, policy.Direct},
	} {
		if got := c.routeFlowLocked(flowKey{Target: tc.target, AppID: tc.app}); got != tc.route {
			t.Errorf("%s / %s: got %v want %v", tc.target, tc.app, got, tc.route)
		}
	}
}

func TestRecoveryIsScopedAndFallbackMemoryIsBounded(t *testing.T) {
	c := testTrafficClient(t)
	c.ready = true
	c.config.Profile.Rules = []string{"first.example", "second.example"}

	c.failVPNLocked(flowKey{Target: "first.example"})
	c.failVPNLocked(flowKey{Target: "second.example"})
	c.recoverVPNLocked(flowKey{Target: "first.example"})
	if !c.vpnFailed {
		t.Fatal("one reply concealed another failing peer")
	}
	if c.routeFlowLocked(flowKey{Target: "first.example"}) != policy.VPN || c.routeFlowLocked(flowKey{Target: "second.example"}) != policy.VPN {
		t.Fatal("recovery changed unrelated route")
	}
	c.recoverVPNLocked(flowKey{Target: "second.example"})
	if c.vpnFailed {
		t.Fatal("recovery was not reported")
	}
	for i := 0; i < 1100; i++ {
		c.failVPNLocked(flowKey{Target: time.Unix(int64(i), 0).String()})
	}
	if len(c.vpnFailures) > 1000 {
		t.Fatal("unbounded failed peer cache")
	}
	for key := range c.vpnFailures {
		c.vpnFailures[key] = time.Now().Add(-time.Second)
	}
	c.recoverVPNLocked(flowKey{})
	if len(c.vpnFailures) != 0 {
		t.Fatal("expired fallback entries retained")
	}
}
