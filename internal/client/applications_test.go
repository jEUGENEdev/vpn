package client

import (
	"context"
	"io"
	"net"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/jEUGENEdev/vpn/internal/model"
	"github.com/jEUGENEdev/vpn/internal/policy"
	"github.com/jEUGENEdev/vpn/internal/transport"
)

func testApp(name string) model.ApplicationInfo {
	return model.ApplicationInfo{ID: strings.Repeat(name, 64), Name: "Browser " + name, Path: "/apps/" + name, Platform: "linux"}
}
func testTrafficClient(t *testing.T) *Client {
	t.Helper()
	c, e := New(t.TempDir(), &transport.Dialer{})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(c.Close)
	return c
}
func observe(t *testing.T, c *Client, target string, app model.ApplicationInfo, at time.Time) {
	t.Helper()
	c.mu.Lock()
	c.observeLocked(target, app, at)
	c.mu.Unlock()
}
func pendingRequests(c *Client) []model.Request {
	return c.State().(map[string]any)["requests"].([]model.Request)
}
func TestOnlyRepeatedDirectFailuresAreSuggestedAndSuccessClears(t *testing.T) {
	c := testTrafficClient(t)
	app := testApp("a")
	now := time.Now()
	observe(t, c, "api.example.com", app, now)
	if len(pendingRequests(c)) != 0 || len(c.State().(map[string]any)["pending_applications"].([]model.Application)) != 0 {
		t.Fatal("successful/untested traffic produced a suggestion")
	}
	c.directFailure("api.example.com", app.ID, now)
	if len(pendingRequests(c)) != 0 {
		t.Fatal("one transient failure produced a suggestion")
	}
	c.directFailure("api.example.com", app.ID, now.Add(time.Second))
	requests := pendingRequests(c)
	if len(requests) != 1 || len(requests[0].Sources) != 1 || requests[0].Sources[0].ID != app.ID {
		t.Fatalf("missing source: %+v", requests)
	}
	if len(c.State().(map[string]any)["pending_applications"].([]model.Application)) != 1 {
		t.Fatal("new failed app has no prompt")
	}
	c.directRecovered("api.example.com", app.ID, now.Add(2*time.Second))
	c.requests = []model.Request{{Target: "api.example.com", DirectFailed: true}}
	if len(pendingRequests(c)) != 0 || len(c.pending) != 0 || len(c.resolved) != 1 {
		t.Fatal("recovery did not remove stale report")
	}
	if len(c.State().(map[string]any)["pending_applications"].([]model.Application)) != 0 {
		t.Fatal("recovered app still prompts")
	}
	// A later single failure must not reuse the old burst.
	c.directFailure("api.example.com", app.ID, now.Add(3*time.Second))
	if len(c.pending) != 0 || len(pendingRequests(c)) != 0 {
		t.Fatal("old failure burst survived recovery")
	}
}

func TestDirectFailureEventsKeepTheirActualSource(t *testing.T) {
	for _, decision := range []string{"pending", "addresses", "unknown"} {
		t.Run(decision, func(t *testing.T) {
			c := testTrafficClient(t)
			now := time.Now()
			app := testApp("a")
			target := "api.example.com"
			observe(t, c, target, app, now)
			if decision == "unknown" {
				// Another, identified app used this address successfully. That
				// must not make it the owner of an unidentified failing flow.
				app = model.ApplicationInfo{}
				observe(t, c, target, app, now)
			} else {
				known := c.apps[app.ID]
				known.Decision = decision
				c.apps[app.ID] = known
			}
			c.directFailure(target, app.ID, now)
			c.directFailure(target, app.ID, now.Add(time.Second))
			items := c.Events.List()
			if len(items) != 1 || items[0].Target != target {
				t.Fatalf("missing or duplicate event: %+v", items)
			}
			if decision == "unknown" {
				if items[0].Source != nil {
					t.Fatalf("guessed source from another connection: %+v", items[0])
				}
			} else if items[0].Source == nil || *items[0].Source != app {
				t.Fatalf("source missing: %+v", items[0])
			}
			c.directRecovered(target, app.ID, now.Add(2*time.Second))
			delete(c.apps, app.ID)
			if c.Events.List()[0].Target != target || (decision != "unknown" && *c.Events.List()[0].Source != app) {
				t.Fatal("current traffic changed historical event context")
			}
		})
	}
}

func TestFallbackConnectionEventIncludesSource(t *testing.T) {
	c := testTrafficClient(t)
	c.config.Pinned = []string{"127.0.0.1"}
	app := testApp("b")
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	conn, err := c.dialApplication(context.Background(), "tcp", "127.0.0.1", uint16(ln.Addr().(*net.TCPAddr).Port), app)
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	items := c.Events.List()
	if len(items) != 1 || items[0].Target != "127.0.0.1" || items[0].Source == nil || *items[0].Source != app {
		t.Fatalf("fallback lost its source: %+v", items)
	}
}

func TestRuleSourcesUseLocalObservationsAndDomainBoundaries(t *testing.T) {
	c := testTrafficClient(t)
	c.config.Profile.Rules = []string{"example.com", "8.8.8.8", "untouched.example.org"}
	c.config.Pinned = []string{"2001:db8::1"}
	now := time.Now()
	app, other := testApp("a"), testApp("b")
	observe(t, c, "api.example.com", app, now)
	observe(t, c, "cdn.example.com", app, now)
	observe(t, c, "unknown.example.com", model.ApplicationInfo{}, now)
	observe(t, c, "notexample.com", other, now)
	observe(t, c, "8.8.8.8", other, now)
	observe(t, c, "2001:db8::1", app, now)
	sources := c.State().(map[string]any)["rule_sources"].(map[string]model.RuleSources)
	if len(sources) != 3 {
		t.Fatalf("unobserved rule got sources: %+v", sources)
	}
	domain := sources["example.com"]
	if len(domain.Sources) != 1 || domain.Sources[0] != app || !domain.Unknown {
		t.Fatalf("domain sources not deduplicated or crossed a boundary: %+v", domain)
	}
	if ip := sources["8.8.8.8"]; len(ip.Sources) != 1 || ip.Sources[0] != other || ip.Unknown {
		t.Fatalf("IP source mixed with domain: %+v", ip)
	}
	if ip := sources["2001:db8::1"]; len(ip.Sources) != 1 || ip.Sources[0] != app {
		t.Fatalf("pending protection lost source: %+v", ip)
	}
}
func TestHistoricSuccessesAndExpiredFailuresDoNotSuggest(t *testing.T) {
	c := testTrafficClient(t)
	now := time.Now()
	c.requests = []model.Request{{Target: "legacy.example.com", Count: 900, FirstSeen: now}}
	observe(t, c, "quiet.example.com", model.ApplicationInfo{}, now.Add(-time.Hour))
	c.directFailure("quiet.example.com", "", now.Add(-time.Hour))
	c.directFailure("quiet.example.com", "", now.Add(-time.Hour+time.Second))
	if len(pendingRequests(c)) != 0 {
		t.Fatal("historic discovery or expired failure was suggested")
	}
}

func TestAddressDecisionsTakePrecedenceOverApplicationPrompts(t *testing.T) {
	c := testTrafficClient(t)
	app := testApp("a")
	now := time.Now()
	observe(t, c, "api.example.com", app, now)
	c.directFailure("api.example.com", app.ID, now)
	c.directFailure("api.example.com", app.ID, now.Add(time.Second))
	pending := func() int { return len(c.State().(map[string]any)["pending_applications"].([]model.Application)) }
	if pending() != 1 {
		t.Fatal("failed new app should initially have a prompt")
	}
	c.dismissed["example.com"] = true
	if pending() != 0 {
		t.Fatal("an ignored address still prompted for application trust")
	}
	delete(c.dismissed, "example.com")
	c.config.Profile.Rules = []string{"example.com"}
	if pending() != 0 {
		t.Fatal("an address already routed by an explicit rule still prompted")
	}
}
func TestStableGroupingSourcesAndPublicSuffixBoundaries(t *testing.T) {
	c := testTrafficClient(t)
	now := time.Now()
	app := testApp("b")
	hosts := []string{"api.example.co.uk", "cdn.example.co.uk", "one.github.io", "two.github.io", "8.8.8.8"}
	for i, host := range hosts {
		at := now.Add(time.Duration(i) * time.Second)
		observe(t, c, host, app, at)
		c.directFailure(host, app.ID, at)
		c.directFailure(host, app.ID, at.Add(time.Millisecond))
	}
	first := c.State().(map[string]any)["request_groups"].([]model.RequestGroup)
	if len(first) != 4 || first[0].Target != "example.co.uk" || len(first[0].Requests) != 2 || first[3].Target != "8.8.8.8" {
		t.Fatalf("bad grouping: %+v", first)
	}
	for i := 0; i < 50; i++ {
		next := c.State().(map[string]any)["request_groups"].([]model.RequestGroup)
		for j := range first {
			if first[j].Target != next[j].Target {
				t.Fatal("map iteration reordered groups")
			}
		}
	}
	c.dismissed["example.co.uk"] = true
	if len(pendingRequests(c)) != 3 {
		t.Fatal("parent dismissal did not hide subdomains")
	}
}
func TestApplicationTrustIsLocalPersistentAndAddressRulesWin(t *testing.T) {
	c := testTrafficClient(t)
	app := testApp("a")
	other := testApp("b")
	now := time.Now()
	observe(t, c, "example.com", app, now)
	observe(t, c, "example.com", other, now)
	if _, err := c.Action(context.Background(), "applications", map[string]any{"id": "forged", "decision": "trusted"}); err == nil {
		t.Fatal("unknown application trusted")
	}
	if _, err := c.Action(context.Background(), "applications", map[string]any{"id": app.ID, "decision": "trusted"}); err != nil {
		t.Fatal(err)
	}
	if c.routeLocked("example.com", app.ID) != policy.Direct {
		t.Fatal("unacknowledged app trust blocked direct")
	}
	c.ready = true
	c.config.Profile.AppUUID = "app-credential"
	if c.routeLocked("example.com", app.ID) != policy.AppVPN || c.routeLocked("example.com", other.ID) != policy.Direct || c.routeLocked("example.com", "") != policy.Direct {
		t.Fatal("app trust widened other applications")
	}
	c.config.Profile.Rules = []string{"example.com"}
	if c.routeLocked("api.example.com", app.ID) != policy.VPN {
		t.Fatal("application route took precedence over address rule")
	}
	c.ready = false
	if c.routeLocked("elsewhere.org", app.ID) != policy.Direct {
		t.Fatal("offline trusted app blocked direct")
	}
	dir := c.dir
	c.Close()
	reopened, err := New(dir, &transport.Dialer{})
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if reopened.apps[app.ID].Decision != "trusted" {
		t.Fatal("trust not persisted")
	}
	if reopened.routeLocked("elsewhere.org", app.ID) != policy.Direct {
		t.Fatal("restart blocked direct fallback")
	}
}
func TestTrustClosesExistingDirectFlowAndRevocationKeepsAddressRules(t *testing.T) {
	c := testTrafficClient(t)
	app := testApp("a")
	observe(t, c, "example.com", app, time.Now())
	left, right := net.Pipe()
	defer right.Close()
	c.active[left] = activeFlow{Target: "example.com", AppID: app.ID, Route: policy.Direct}
	c.Action(context.Background(), "applications", map[string]any{"id": app.ID, "decision": "trusted"})
	if _, err := left.Write([]byte("leak")); err == nil {
		t.Fatal("old direct flow survived trust")
	}
	c.config.Profile.Rules = []string{"example.com"}
	c.Action(context.Background(), "applications", map[string]any{"id": app.ID, "decision": "addresses"})
	if c.routeLocked("example.com", app.ID) != policy.Direct {
		t.Fatal("revoking app trust blocked network")
	}
}
func TestReadFailureCountsOncePerConnection(t *testing.T) {
	c := testTrafficClient(t)
	observe(t, c, "example.com", model.ApplicationInfo{}, time.Now())
	left, right := net.Pipe()
	c.active[left] = activeFlow{Target: "example.com", Route: policy.Direct}
	tracked := &tracked{Conn: left, c: c}
	defer tracked.Close()
	right.Close()
	for i := 0; i < 3; i++ {
		if _, err := tracked.Read(make([]byte, 1)); err != io.EOF {
			t.Fatal(err)
		}
	}
	if len(c.pending) != 0 || len(c.observed["example.com"].Failures[""].Times) != 1 {
		t.Fatal("one connection counted as repeated failures")
	}
}
func TestUnknownSourceIsExplicitAndCannotGrantTrust(t *testing.T) {
	c := testTrafficClient(t)
	now := time.Now()
	observe(t, c, "8.8.8.8", model.ApplicationInfo{}, now)
	c.directFailure("8.8.8.8", "", now)
	c.directFailure("8.8.8.8", "", now.Add(time.Second))
	r := pendingRequests(c)
	if len(r) != 1 || !r[0].Unknown || len(r[0].Sources) != 0 {
		t.Fatal("unknown source was guessed")
	}
}

func TestFailuresDoNotBorrowIdentityFromSuccessfulApps(t *testing.T) {
	c := testTrafficClient(t)
	now := time.Now()
	a, b := testApp("a"), testApp("b")
	observe(t, c, "example.com", a, now)
	observe(t, c, "example.com", b, now)
	c.directFailure("example.com", a.ID, now)
	c.directFailure("example.com", a.ID, now.Add(time.Second))
	c.directRecovered("example.com", b.ID, now.Add(2*time.Second))
	requests := pendingRequests(c)
	if len(requests) != 1 || len(requests[0].Sources) != 1 || requests[0].Sources[0].ID != a.ID {
		t.Fatal("failure attributed to a healthy application")
	}
	prompts := c.State().(map[string]any)["pending_applications"].([]model.Application)
	if len(prompts) != 1 || prompts[0].ID != a.ID {
		t.Fatal("healthy application prompted")
	}
}

func TestSilentDirectConnectionsRequireDataAndRecoverOnLateResponse(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c := testTrafficClient(t)
		app := testApp("a")
		observe(t, c, "silent.example.com", app, time.Now())
		connection := func() (*tracked, net.Conn) {
			left, right := net.Pipe()
			c.mu.Lock()
			c.active[left] = activeFlow{Target: "silent.example.com", AppID: app.ID, Route: policy.Direct}
			c.mu.Unlock()
			conn := &tracked{Conn: left, c: c}
			t.Cleanup(func() { conn.Close(); right.Close() })
			go io.Copy(io.Discard, right)
			return conn, right
		}
		idle, _ := connection()
		time.Sleep(firstResponseTimeout + time.Second)
		if len(c.observed["silent.example.com"].Failures) != 0 {
			t.Fatal("an idle connection counted as an unavailable address")
		}
		idle.Close()
		first, _ := connection()
		first.Write([]byte("request one"))
		time.Sleep(firstResponseTimeout + time.Second)
		if len(pendingRequests(c)) != 0 {
			t.Fatal("one silent request produced a suggestion")
		}
		second, remote := connection()
		second.Write([]byte("request two"))
		time.Sleep(firstResponseTimeout + time.Second)
		if len(pendingRequests(c)) != 1 {
			t.Fatal("repeated silent requests were not suggested")
		}
		// The timeout observes only; the same connection can still receive data.
		go remote.Write([]byte("late reply"))
		if _, err := io.ReadFull(second, make([]byte, len("late reply"))); err != nil {
			t.Fatal(err)
		}
		if len(pendingRequests(c)) != 0 {
			t.Fatal("late response did not clear the suggestion")
		}
	})
}

func TestSuccessfulAndCancelledRequestsDoNotBecomeTimeoutFailures(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c := testTrafficClient(t)
		for _, cancel := range []bool{false, true} {
			observe(t, c, "working.example.com", model.ApplicationInfo{}, time.Now())
			left, right := net.Pipe()
			c.mu.Lock()
			c.active[left] = activeFlow{Target: "working.example.com", Route: policy.Direct}
			c.mu.Unlock()
			conn := &tracked{Conn: left, c: c}
			go io.Copy(io.Discard, right)
			conn.Write([]byte("request"))
			if !cancel {
				go right.Write([]byte("response"))
				io.ReadFull(conn, make([]byte, len("response")))
			}
			conn.Close()
			right.Close()
			time.Sleep(firstResponseTimeout + time.Second)
			if len(c.observed["working.example.com"].Failures) != 0 {
				t.Fatal("successful or cancelled request counted as a failure")
			}
		}
	})
}
