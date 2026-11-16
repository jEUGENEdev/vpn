package client

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/jEUGENEdev/vpn/internal/model"
	"github.com/jEUGENEdev/vpn/internal/owner"
	"github.com/jEUGENEdev/vpn/internal/policy"
	"github.com/jEUGENEdev/vpn/internal/secure"
)

type observation struct {
	Failures               map[string]*directFailureState
	LastFailure, Recovered time.Time
	Failed                 bool
	FirstSeen, LastSeen    time.Time
	Count                  int
	Sources                map[string]model.ApplicationInfo
	Unknown                bool
}
type directFailureState struct {
	Times  []time.Time
	Last   time.Time
	Failed bool
}

type activeFlow struct {
	Target, AppID string
	Route         policy.Route
}

func validApplication(a model.ApplicationInfo) bool {
	id, err := hex.DecodeString(a.ID)
	return err == nil && len(id) == 32 && len(a.Name) > 0 && len(a.Name) <= 200 && len(a.Path) > 0 && len(a.Path) <= 4096 && (a.Platform == "android" || a.Platform == "windows" || a.Platform == "darwin" || a.Platform == "linux")
}
func (c *Client) loadApplications() error {
	raw, err := os.ReadFile(filepath.Join(c.dir, "applications.json"))
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	var apps map[string]model.Application
	if err = json.Unmarshal(raw, &apps); err != nil {
		return errors.New("повреждён список приложений")
	}
	if len(apps) > 512 {
		return errors.New("слишком много приложений")
	}
	for id, a := range apps {
		if id != a.ID || !validApplication(a.ApplicationInfo) || (a.Decision != "pending" && a.Decision != "addresses" && a.Decision != "trusted") {
			return errors.New("неверное разрешение приложения")
		}
	}
	if apps != nil {
		c.apps = apps
	}
	return nil
}
func (c *Client) saveApplications(apps map[string]model.Application) error {
	raw, err := json.Marshal(apps)
	if err != nil {
		return err
	}
	return secure.Save(filepath.Join(c.dir, "applications.json"), raw)
}
func (c *Client) SetOwnerLookup(lookup owner.Lookup) {
	c.mu.Lock()
	c.ownerLookup = lookup
	c.mu.Unlock()
}
func (c *Client) lookupApplication(ctx context.Context, network string, source, dest netip.AddrPort) model.ApplicationInfo {
	c.mu.RLock()
	lookup := c.ownerLookup
	c.mu.RUnlock()
	if lookup == nil {
		return model.ApplicationInfo{}
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	app, err := lookup(ctx, network, source, dest)
	if err != nil || !validApplication(app) {
		return model.ApplicationInfo{}
	}
	return app
}

// Caller holds c.mu. Persistent decisions are written only on first discovery
// or a user's action, not on every packet or polling interval.
func (c *Client) observeLocked(target string, app model.ApplicationInfo, now time.Time) {
	if validApplication(app) {
		a, exists := c.apps[app.ID]
		if !exists && len(c.apps) < 512 {
			a = model.Application{ApplicationInfo: app, Decision: "pending", FirstSeen: now, LastSeen: now, Target: target}
			c.apps[app.ID] = a
			_ = c.saveApplications(c.apps)
		} else if exists {
			a.LastSeen = now
			a.Target = target
			c.apps[app.ID] = a
		}
	}
	o, exists := c.observed[target]
	if !exists {
		if len(c.observed) >= 1000 {
			oldest := ""
			var at time.Time
			for host, v := range c.observed {
				if (!v.Failed || now.Sub(v.LastFailure) >= 30*time.Minute) && (oldest == "" || v.LastSeen.Before(at)) {
					oldest = host
					at = v.LastSeen
				}
			}
			if oldest == "" {
				return
			}
			delete(c.observed, oldest)
			delete(c.pending, oldest)
			delete(c.sent, oldest)
		}
		o = &observation{FirstSeen: now, Sources: map[string]model.ApplicationInfo{}}
		c.observed[target] = o
	}
	o.LastSeen = now
	o.Count++
	if validApplication(app) {
		if len(o.Sources) < 16 {
			o.Sources[app.ID] = app
		} else if _, ok := o.Sources[app.ID]; !ok {
			o.Unknown = true
		}
	} else {
		o.Unknown = true
	}
}

// Address rules always win. Trust extends routing only for an OS-identified
// application, and requires a separate device credential acknowledged by API.
func (c *Client) routeLocked(target, appID string) policy.Route {
	route := policy.Decide(c.effectiveRules(), target, c.ready)
	if route != policy.Direct {
		return route
	}
	if app, ok := c.apps[appID]; ok && app.Decision == "trusted" {
		if !c.ready || c.config.Profile.AppUUID == "" {
			return policy.Block
		}
		return policy.AppVPN
	}
	return route
}
func (c *Client) hasTrustedAppsLocked() bool {
	for _, a := range c.apps {
		if a.Decision == "trusted" {
			return true
		}
	}
	return false
}

// Caller holds c.change, but not c.mu.
func (c *Client) ensureApplicationTunnel(ctx context.Context) error {
	c.mu.RLock()
	enabled := c.hasTrustedAppsLocked()
	configured := c.config.Profile.AppUUID != ""
	logged := c.config.Profile.Token != ""
	c.mu.RUnlock()
	if enabled == configured || !logged {
		return nil
	}
	var profile model.Profile
	if err := c.request(ctx, "POST", "/api/app-vpn", map[string]bool{"enabled": enabled}, &profile); err != nil {
		return err
	}
	return c.apply(profile)
}
func (c *Client) applicationAction(ctx context.Context, data any) (any, error) {
	fields, ok := data.(map[string]any)
	if !ok {
		return nil, errors.New("неверное приложение")
	}
	id, _ := fields["id"].(string)
	decision, _ := fields["decision"].(string)
	if decision != "trusted" && decision != "addresses" {
		return nil, errors.New("неверное решение")
	}
	c.change.Lock()
	defer c.change.Unlock()
	c.mu.Lock()
	app, ok := c.apps[id]
	if !ok {
		c.mu.Unlock()
		return nil, errors.New("приложение ещё не обнаружено на этом устройстве")
	}
	next := make(map[string]model.Application, len(c.apps))
	for key, value := range c.apps {
		next[key] = value
	}
	app.Decision = decision
	next[id] = app
	if err := c.saveApplications(next); err != nil {
		c.mu.Unlock()
		return nil, err
	}
	c.apps = next
	for conn, flow := range c.active {
		if flow.AppID == id {
			delete(c.active, conn)
			conn.Close()
		}
	}
	c.mu.Unlock()
	if err := c.ensureApplicationTunnel(ctx); err != nil {
		return map[string]any{"ok": true, "pending": true, "message": "Решение сохранено. Для VPN приложения ждём подтверждения сервера."}, nil
	}
	return map[string]bool{"ok": true}, nil
}
func (c *Client) applicationSnapshotLocked() ([]model.Application, []model.Application) {
	apps := make([]model.Application, 0, len(c.apps))
	pending := []model.Application{}
	for _, a := range c.apps {
		apps = append(apps, a)
	}
	sort.Slice(apps, func(i, j int) bool {
		if apps[i].FirstSeen.Equal(apps[j].FirstSeen) {
			return apps[i].ID < apps[j].ID
		}
		return apps[i].FirstSeen.Before(apps[j].FirstSeen)
	})
	for _, a := range apps {
		if a.Decision == "pending" {
			for target, o := range c.observed {
				if o.Failed && time.Since(o.LastFailure) < 30*time.Minute {
					if failure := o.Failures[a.ID]; failure != nil && failure.Failed && time.Since(failure.Last) < 30*time.Minute {
						a.Target = target
						pending = append(pending, a)
						break
					}
				}
			}
		}
	}
	return apps, pending
}
func (c *Client) isDismissedLocked(target string) bool {
	for rule := range c.dismissed {
		if policy.Matches(rule, target) {
			return true
		}
	}
	return false
}
func (c *Client) requestsLocked() []model.Request {
	requests := []model.Request{}
	seen := map[string]bool{}
	appendRequest := func(r model.Request) {
		o := c.observed[r.Target]
		if o != nil && !o.Recovered.IsZero() && !o.Failed {
			return
		}
		recentLocal := o != nil && o.Failed && time.Since(o.LastFailure) < 30*time.Minute
		if !r.DirectFailed && !recentLocal {
			return
		}
		if seen[r.Target] || r.Dismissed || c.isDismissedLocked(r.Target) || policy.Approved(c.effectiveRules(), r.Target) {
			return
		}
		seen[r.Target] = true
		if o := c.observed[r.Target]; o != nil {
			if r.FirstSeen.IsZero() || o.FirstSeen.Before(r.FirstSeen) {
				r.FirstSeen = o.FirstSeen
			}
			if o.LastSeen.After(r.LastSeen) {
				r.LastSeen = o.LastSeen
			}
			if o.Count > r.Count {
				r.Count = o.Count
			}
			failedSources := map[string]model.ApplicationInfo{}
			r.Unknown = false
			for id, failure := range o.Failures {
				if failure.Failed && time.Since(failure.Last) < 30*time.Minute {
					if app, ok := o.Sources[id]; ok {
						failedSources[id] = app
					} else {
						r.Unknown = true
					}
				}
			}
			r.Sources = sourceList(failedSources)
			if len(r.Sources) == 0 {
				r.Unknown = true
			}
		} else {
			r.Unknown = true
		}
		requests = append(requests, r)
	}
	for _, r := range c.requests {
		appendRequest(r)
	}
	for target, at := range c.pending {
		appendRequest(model.Request{Target: target, FirstSeen: at, LastSeen: at, Count: 1})
	}
	sort.Slice(requests, func(i, j int) bool {
		if requests[i].FirstSeen.Equal(requests[j].FirstSeen) {
			return requests[i].Target < requests[j].Target
		}
		return requests[i].FirstSeen.Before(requests[j].FirstSeen)
	})
	return requests
}
func sourceList(sources map[string]model.ApplicationInfo) []model.ApplicationInfo {
	out := make([]model.ApplicationInfo, 0, len(sources))
	for _, a := range sources {
		out = append(out, a)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Name == out[j].Name {
			return out[i].ID < out[j].ID
		}
		return out[i].Name < out[j].Name
	})
	return out
}
func groupRequests(requests []model.Request) []model.RequestGroup {
	groups := []model.RequestGroup{}
	indices := map[string]int{}
	sources := map[string]map[string]model.ApplicationInfo{}
	for _, r := range requests {
		target := policy.Group(r.Target)
		index, exists := indices[target]
		if !exists {
			index = len(groups)
			indices[target] = index
			groups = append(groups, model.RequestGroup{Target: target, FirstSeen: r.FirstSeen, LastSeen: r.LastSeen, Requests: []model.Request{}})
			sources[target] = map[string]model.ApplicationInfo{}
		}
		g := &groups[index]
		g.Requests = append(g.Requests, r)
		g.Count += r.Count
		g.Unknown = g.Unknown || r.Unknown
		if r.FirstSeen.Before(g.FirstSeen) {
			g.FirstSeen = r.FirstSeen
		}
		if r.LastSeen.After(g.LastSeen) {
			g.LastSeen = r.LastSeen
		}
		for _, a := range r.Sources {
			sources[target][a.ID] = a
		}
	}
	for i := range groups {
		g := &groups[i]
		g.Sources = sourceList(sources[g.Target])
		sort.Slice(g.Requests, func(i, j int) bool { return g.Requests[i].Target < g.Requests[j].Target })
	}
	return groups
}

// Only repeated failures of real direct connections create suggestions. A
// successful response clears both the local proposal and this device's report.
func (c *Client) directFailure(target, appID string, now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.directFailureLocked(target, appID, now)
}
func (c *Client) directFailureLocked(target, appID string, now time.Time) {
	if c.closed || c.routeLocked(target, appID) != policy.Direct || c.isDismissedLocked(target) {
		return
	}
	o := c.observed[target]
	if o == nil {
		return
	}
	if o.Failures == nil {
		o.Failures = map[string]*directFailureState{}
	}
	f := o.Failures[appID]
	if f == nil {
		if len(o.Failures) >= 17 {
			return
		}
		f = &directFailureState{}
		o.Failures[appID] = f
	}
	recent := f.Times[:0]
	for _, at := range f.Times {
		if now.Sub(at) < time.Minute {
			recent = append(recent, at)
		}
	}
	f.Times = append(recent, now)
	if len(f.Times) > 8 {
		f.Times = f.Times[len(f.Times)-8:]
	}
	f.Last = now
	o.LastFailure = now
	if len(f.Times) < 2 {
		return
	}
	f.Failed = true
	o.Failed = true
	if len(c.pending) < 1000 {
		c.pending[target] = now
	}
	delete(c.resolved, target)
	if app, ok := c.apps[appID]; ok && app.Decision == "pending" {
		c.Events.NewApplication(now, app.ID, app.Name, target)
	}
	c.Events.DirectUnavailable(now, target)
}
func (c *Client) directRecovered(target, appID string, now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	o := c.observed[target]
	if o == nil {
		return
	}
	wasFailed := o.Failed
	delete(o.Failures, appID)
	o.Failed = false
	for _, f := range o.Failures {
		if f.Failed && now.Sub(f.Last) < 30*time.Minute {
			o.Failed = true
			break
		}
	}
	if o.Failed {
		return
	}
	if wasFailed {
		c.resolved[target] = now
	}
	o.Recovered = now
	delete(c.pending, target)
	delete(c.sent, target)
}
