package client

import (
	"context"
	"errors"
	"sort"

	"github.com/jEUGENEdev/vpn/internal/model"
	"github.com/jEUGENEdev/vpn/internal/policy"
)

// Caller holds mu (or is constructing the client). Only locally identified
// applications can receive restored trust; a server rule never invents an app.
func (c *Client) mergeApplicationRulesLocked(p model.Profile, acknowledged []model.ApplicationRuleChange) (map[string]model.Application, error) {
	if len(p.ApplicationRules) > 512 {
		return nil, errors.New("слишком много разрешений приложений")
	}
	rules := make(map[string]model.ApplicationRule, len(p.ApplicationRules))
	for _, rule := range p.ApplicationRules {
		if !rule.Valid() || rule.Platform != c.identity.Platform {
			return nil, errors.New("неверное разрешение приложения в профиле")
		}
		if _, duplicate := rules[rule.ID]; duplicate {
			return nil, errors.New("повтор разрешения приложения в профиле")
		}
		rules[rule.ID] = rule
	}
	confirmed := make(map[string]bool, len(acknowledged))
	for _, change := range acknowledged {
		if _, ok := rules[change.ID]; !ok {
			return nil, errors.New("сервер не подтвердил сохранение решения приложения")
		}
		confirmed[change.ID] = true
	}
	apps := make(map[string]model.Application, len(c.apps))
	for id, app := range c.apps {
		if rule, ok := rules[id]; ok && rule.Platform == app.Platform && (!app.SyncPending || confirmed[id]) {
			app.Decision = rule.Decision
			app.SyncPending, app.SyncConfirmed = false, true
		}
		apps[id] = app
	}
	return apps, nil
}

func (c *Client) restoredApplicationDecisionLocked(app model.ApplicationInfo) (string, bool) {
	for _, rule := range c.config.Profile.ApplicationRules {
		if rule.ID == app.ID && rule.Platform == app.Platform {
			return rule.Decision, true
		}
	}
	return "pending", false
}

func (c *Client) pendingPolicyCountLocked() int {
	count := len(c.config.Pinned)
	for _, app := range c.apps {
		if app.Platform == c.identity.Platform && app.Decision != "pending" && (app.SyncPending || !app.SyncConfirmed) {
			count++
		}
	}
	return count
}

func (c *Client) pendingPins() []string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return append([]string{}, c.config.Pinned...)
}

// Caller holds change. Unconfirmed decisions survive restart and are retried
// with the latest server revision. Successful GETs clear already-saved pins,
// including the case where the server committed but its response was lost.
func (c *Client) syncSavedPolicy(ctx context.Context) (err error) {
	defer func() {
		c.mu.Lock()
		defer c.mu.Unlock()
		c.policySyncError = ""
		if err != nil {
			c.policySyncError = err.Error()
		}
	}()
	// One rejected address must not prevent unrelated app decisions being saved.
	return errors.Join(c.syncPinnedRules(ctx), c.syncApplicationRules(ctx))
}

func (c *Client) syncPinnedRules(ctx context.Context) error {
	// Bound work per poll so a long migration does not monopolize UI actions.
	pins := c.pendingPins()
	if len(pins) > 32 {
		pins = pins[:32]
	}
	var firstError error
	for _, target := range pins {
		c.mu.RLock()
		revision := c.config.Profile.Revision
		approved := policy.Approved(c.config.Profile.Rules, target)
		c.mu.RUnlock()
		if approved {
			continue
		}
		var result syncResult
		if err := c.request(ctx, "POST", "/api/rules", map[string]any{"target": target, "action": "approve", "revision": revision}, &result); err != nil {
			if firstError == nil {
				firstError = err
			}
			var apiError *APIError
			if errors.As(err, &apiError) && (apiError.Status == 400 || apiError.Status == 409) {
				continue
			}
			break
		}
		if err := c.apply(result.Profile); err != nil {
			return err
		}
	}
	return firstError
}

func (c *Client) syncApplicationRules(ctx context.Context) error {
	c.mu.RLock()
	changes := []model.ApplicationRuleChange{}
	for id, app := range c.apps {
		if app.Platform == c.identity.Platform && app.Decision != "pending" && (app.SyncPending || !app.SyncConfirmed) {
			changes = append(changes, model.ApplicationRuleChange{ID: id, Decision: app.Decision, OnlyIfAbsent: !app.SyncPending})
		}
	}
	supported := c.config.Profile.ApplicationRules != nil
	logged := c.config.Profile.Token != ""
	c.mu.RUnlock()
	if len(changes) == 0 {
		return nil
	}
	if !logged {
		return errors.New("войдите в аккаунт, чтобы сохранить решения приложений на сервере")
	}
	if !supported {
		return errors.New("для сохранения решений приложений обновите сервер приложения «Сеть»")
	}
	sort.Slice(changes, func(i, j int) bool { return changes[i].ID < changes[j].ID })
	if len(changes) > 64 {
		changes = changes[:64]
	}
	var profile model.Profile
	if err := c.request(ctx, "POST", "/api/application-rules", map[string]any{"changes": changes}, &profile); err != nil {
		return err
	}
	return c.applyProfile(profile, changes)
}
