package server

import (
	"errors"
	"net/http"
	"sort"

	"github.com/jEUGENEdev/vpn/internal/model"
	"github.com/jEUGENEdev/vpn/internal/store"
)

func applicationRules(a store.Account, platform string) []model.ApplicationRule {
	rules := []model.ApplicationRule{}
	for _, rule := range a.ApplicationRules {
		if rule.Platform == platform {
			rules = append(rules, rule)
		}
	}
	sort.Slice(rules, func(i, j int) bool { return rules[i].ID < rules[j].ID })
	return rules
}

// Save individual decisions, never a replacement snapshot from one device.
// Legacy clients migrate with insert-only semantics so stale local choices
// cannot overwrite a decision already saved by another installation.
func (s *Server) saveApplicationRules(w http.ResponseWriter, r *http.Request) {
	d, _, err := s.device(r)
	if err != nil {
		fail(w, 401, err)
		return
	}
	var input struct {
		Changes []model.ApplicationRuleChange `json:"changes"`
	}
	if !body(w, r, &input) {
		return
	}
	if len(input.Changes) == 0 || len(input.Changes) > 64 {
		fail(w, 400, errors.New("нужно от 1 до 64 решений по приложениям"))
		return
	}
	for _, change := range input.Changes {
		if !(model.ApplicationRule{ID: change.ID, Platform: d.Platform, Decision: change.Decision}).Valid() {
			fail(w, 400, errors.New("неверное разрешение приложения"))
			return
		}
	}
	// Only metadata changes here; do not reconfigure any device transport.
	err = s.Store.Update(func(st *store.State) error {
		if !stillAuthorized(st, d) {
			return ErrForbidden
		}
		a := st.Accounts[d.AccountID]
		if a.ApplicationRules == nil {
			a.ApplicationRules = map[string]model.ApplicationRule{}
		}
		count := len(applicationRules(a, d.Platform))
		changed := false
		for _, change := range input.Changes {
			key := d.Platform + ":" + change.ID
			old, exists := a.ApplicationRules[key]
			if exists && (change.OnlyIfAbsent || old.Decision == change.Decision) {
				continue
			}
			if !exists {
				if count >= 512 {
					return errors.New("лимит сохранённых разрешений приложений для этой платформы (512)")
				}
				count++
			}
			a.ApplicationRules[key] = model.ApplicationRule{ID: change.ID, Platform: d.Platform, Decision: change.Decision}
			changed = true
		}
		if changed {
			a.Revision++
			st.Accounts[a.ID] = a
		}
		return nil
	})
	if err != nil {
		status := http.StatusConflict
		if errors.Is(err, ErrForbidden) {
			status = http.StatusUnauthorized
		}
		fail(w, status, err)
		return
	}
	d, a, err := s.device(r)
	if err != nil {
		fail(w, 401, err)
		return
	}
	JSON(w, 200, s.profile(d, a, ""))
}
