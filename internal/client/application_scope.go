package client

import (
	"errors"
	"maps"
	"reflect"
	"sort"
	"time"

	"github.com/jEUGENEdev/vpn/internal/model"
)

// Android scopes the OS VPN itself, not just the upstream route. Desktop
// controllers deliberately do not implement this optional interface.
type ApplicationScopeController interface {
	ApplyApplicationScope(all bool, apps []model.ApplicationInfo) error
}

func applicationScope(mode string, apps map[string]model.Application, installed map[string]bool) (bool, []model.ApplicationInfo) {
	selected := []model.ApplicationInfo{}
	for _, app := range apps {
		if installed != nil && !installed[app.ID] {
			continue
		}
		if app.Decision == "trusted" || app.Decision == "addresses" {
			selected = append(selected, app.ApplicationInfo)
		}
	}
	sort.Slice(selected, func(i, j int) bool { return selected[i].ID < selected[j].ID })
	return mode == TrafficAll, selected
}

func (c *Client) ApplicationScope() (bool, []model.ApplicationInfo) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return applicationScope(c.trafficModeLocked(), c.apps, c.appInventory)
}

// Drop flows and invalidate late dial results when Android replaces the TUN.
func (c *Client) NetworkScopeChanged() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.routeEpoch++
	for flow := range c.active {
		delete(c.active, flow)
		flow.Close()
	}
}

// Caller holds change, never mu. Capture the union BEFORE persisting a grant.
// A failed native call must not grant protection to an app still outside TUN;
// a failed save must not release an app protected by the old policy.
func (c *Client) prepareApplicationScope(mode string, apps map[string]model.Application) error {
	c.mu.RLock()
	installed := c.appInventory
	c.mu.RUnlock()
	return c.prepareInstalledScope(mode, apps, installed)
}

func (c *Client) prepareInstalledScope(mode string, apps map[string]model.Application, installed map[string]bool) error {
	controller, ok := c.power.(ApplicationScopeController)
	if !ok {
		return nil
	}
	all, next := applicationScope(mode, apps, installed)
	oldAll, old := c.ApplicationScope()
	byID := map[string]model.ApplicationInfo{}
	for _, app := range append(old, next...) {
		byID[app.ID] = app
	}
	union := make([]model.ApplicationInfo, 0, len(byID))
	for _, app := range byID {
		union = append(union, app)
	}
	sort.Slice(union, func(i, j int) bool { return union[i].ID < union[j].ID })
	return controller.ApplyApplicationScope(all || oldAll, union)
}

// Caller holds change, never mu. Restrict only after the new policy is saved.
func (c *Client) applyApplicationScope() error {
	controller, ok := c.power.(ApplicationScopeController)
	if !ok {
		return nil
	}
	all, apps := c.ApplicationScope()
	err := controller.ApplyApplicationScope(all, apps)
	c.mu.Lock()
	if err != nil {
		c.powerError = err.Error()
	} else {
		c.powerError = ""
	}
	c.mu.Unlock()
	return err
}

// Applications excluded from TUN cannot discover themselves through traffic.
// Accept a complete, locally signed package inventory from Android instead.
// No names/paths are uploaded by the existing account permission sync.
func (c *Client) SetInstalledApplications(installed []model.ApplicationInfo) error {
	if len(installed) > 512 {
		return errors.New("слишком много установленных приложений")
	}
	c.change.Lock()
	defer c.change.Unlock()
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return errors.New("client stopped")
	}
	// Keep absent apps' decisions for account sync and reinstall. In particular,
	// an unsynced denial must not disappear and restore old server-side trust.
	next := maps.Clone(c.apps)
	inventory := make(map[string]bool, len(installed))
	paths := map[string]bool{}
	for _, info := range installed {
		if !validApplication(info) || info.Platform != "android" || paths[info.Path] || inventory[info.ID] {
			c.mu.Unlock()
			return errors.New("неверный каталог Android")
		}
		paths[info.Path] = true
		inventory[info.ID] = true
		app, exists := c.apps[info.ID]
		if !exists {
			app = model.Application{ApplicationInfo: info, FirstSeen: time.Now()}
			app.Decision, app.SyncConfirmed = c.restoredApplicationDecisionLocked(info)
		}
		app.ApplicationInfo = info
		next[info.ID] = app
	}
	for id, app := range next {
		if !inventory[id] && app.Decision == "pending" {
			delete(next, id)
		}
	}
	if len(next) > 512 {
		c.mu.Unlock()
		return errors.New("слишком много сохранённых приложений")
	}
	mode := c.trafficModeLocked()
	changed := !reflect.DeepEqual(next, c.apps) || !reflect.DeepEqual(inventory, c.appInventory)
	c.mu.Unlock()
	if !changed {
		return c.applyApplicationScope()
	}
	if err := c.prepareInstalledScope(mode, next, inventory); err != nil {
		return err
	}
	c.mu.Lock()
	if err := c.saveApplications(next); err != nil {
		c.mu.Unlock()
		return errors.Join(err, c.applyApplicationScope())
	}
	c.apps = next
	c.appInventory = inventory
	c.routeEpoch++
	for flow := range c.active {
		delete(c.active, flow)
		flow.Close()
	}
	c.mu.Unlock()
	return c.applyApplicationScope()
}
