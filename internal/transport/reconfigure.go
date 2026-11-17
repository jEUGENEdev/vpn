package transport

import (
	"context"
	"slices"
	"strings"

	"github.com/xtls/xray-core/app/proxyman/command"
	"github.com/xtls/xray-core/app/router"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/inbound"
	"github.com/xtls/xray-core/features/routing"
	vless "github.com/xtls/xray-core/proxy/vless/inbound"
	"google.golang.org/protobuf/proto"
)

// Split the generated server config into immutable transport settings and the
// live user/ACL tables. Never use the hot path for other inbound types/configs.
func serverPolicy(config *core.Config) (*core.Config, []*protocol.User, *router.Config) {
	if config == nil || len(config.Inbound) != 1 || config.Inbound[0].Tag != "linevpn-in" {
		return nil, nil, nil
	}
	base := proto.Clone(config).(*core.Config)
	proxy, err := base.Inbound[0].ProxySettings.GetInstance()
	if err != nil {
		return nil, nil, nil
	}
	v, ok := proxy.(*vless.Config)
	if !ok {
		return nil, nil, nil
	}
	users := v.Users
	v.Users = nil
	base.Inbound[0].ProxySettings = serial.ToTypedMessage(v)
	for i, app := range base.App {
		instance, err := app.GetInstance()
		if err != nil {
			return nil, nil, nil
		}
		if rules, ok := instance.(*router.Config); ok {
			static := proto.Clone(rules).(*router.Config)
			static.Rule = nil
			base.App[i] = serial.ToTypedMessage(static)
			return base, users, rules
		}
	}
	return nil, nil, nil
}

func containsMessages[T proto.Message](next, old []T) bool {
	// Empty matcher lists mean unrestricted, not an empty allowed set.
	if len(old) == 0 {
		return len(next) == 0
	}
	if len(next) == 0 {
		return true
	}
	for _, item := range old {
		if !slices.ContainsFunc(next, func(candidate T) bool { return proto.Equal(item, candidate) }) {
			return false
		}
	}
	return true
}

func expandsRule(next, old *router.RoutingRule) bool {
	if next.GetTag() != "allowed" || old.GetTag() != "allowed" {
		return false
	}
	a, b := proto.Clone(next).(*router.RoutingRule), proto.Clone(old).(*router.RoutingRule)
	a.Domain, a.Ip, b.Domain, b.Ip = nil, nil, nil, nil
	return proto.Equal(a, b) && containsMessages(next.Domain, old.Domain) && containsMessages(next.Ip, old.Ip)
}

// Additive changes preserve all accepted XHTTP streams. Credential rotation,
// deletion, expiry, account suspension and ACL removal still replace/cancel the
// instance so previously authorized live streams cannot survive revocation.
// Caller holds Runtime.mu. Xray's user validator and router publish atomically.
func (r *Runtime) expandServerPolicy(next *core.Config) (bool, error) {
	oldBase, oldUsers, oldRules := serverPolicy(r.config)
	newBase, newUsers, newRules := serverPolicy(next)
	if oldBase == nil || newBase == nil || !proto.Equal(oldBase, newBase) {
		return false, nil
	}
	byEmail := make(map[string]*protocol.User, len(newUsers))
	for _, user := range newUsers {
		email := strings.ToLower(user.Email)
		if email == "" || byEmail[email] != nil {
			return false, nil
		}
		byEmail[email] = user
	}
	for _, user := range oldUsers {
		email := strings.ToLower(user.Email)
		if !proto.Equal(user, byEmail[email]) {
			return false, nil
		}
		delete(byEmail, email)
	}
	for _, rule := range newRules.Rule {
		if rule.GetTag() != "allowed" {
			return false, nil
		}
	}
	for _, rule := range oldRules.Rule {
		if !slices.ContainsFunc(newRules.Rule, func(candidate *router.RoutingRule) bool { return expandsRule(candidate, rule) }) {
			return false, nil
		}
	}
	manager, ok := r.instance.GetFeature(inbound.ManagerType()).(inbound.Manager)
	if !ok {
		return false, nil
	}
	router, ok := r.instance.GetFeature(routing.RouterType()).(routing.Router)
	if !ok {
		return false, nil
	}
	handler, err := manager.GetHandler(context.Background(), "linevpn-in")
	if err != nil {
		return false, err
	}
	// Publish ACLs first: new credentials cannot authenticate until their
	// matching routes are available. Existing grants are a subset of these.
	if err = router.AddRule(serial.ToTypedMessage(newRules), false); err != nil {
		return false, err
	}
	for _, user := range byEmail {
		operation := command.AddUserOperation{User: user}
		if err = operation.ApplyInbound(context.Background(), handler); err != nil {
			return false, err
		}
	}
	return true, nil
}
