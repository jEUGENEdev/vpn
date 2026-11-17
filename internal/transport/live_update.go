package transport

import (
	"context"

	"github.com/xtls/xray-core/app/router"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/inbound"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/proxy"
	vlessin "github.com/xtls/xray-core/proxy/vless/inbound"
	"google.golang.org/protobuf/proto"
)

const serverInboundTag = "linevpn-vless"

// Only additive updates are live. Deletion, expiry, key rotation and removal
// of permissions still cancel the old instance, including accepted streams.
// Xray's RemoveUser alone does not revoke already authenticated connections.
func (r *Runtime) extendServer(next *core.Config) bool {
	oldBase, oldUsers, oldRoutes, ok := serverConfigParts(r.config)
	if !ok {
		return false
	}
	newBase, newUsers, newRoutes, ok := serverConfigParts(next)
	if !ok || !proto.Equal(oldBase, newBase) {
		return false
	}
	for email, user := range oldUsers {
		if !proto.Equal(user, newUsers[email]) {
			return false
		}
	}
	for _, before := range oldRoutes.Rule {
		preserved := false
		for _, after := range newRoutes.Rule {
			if preservesRule(before, after) {
				preserved = true
				break
			}
		}
		if !preserved {
			return false
		}
	}
	// All generated rules grant access to exactly one authenticated identity;
	// an inserted deny/redirect rule must never qualify as a safe extension.
	for _, rule := range newRoutes.Rule {
		if rule.GetTag() != "allowed" || len(rule.UserEmail) != 1 || newUsers[rule.UserEmail[0]] == nil {
			return false
		}
	}
	manager, ok := r.instance.GetFeature(inbound.ManagerType()).(inbound.Manager)
	if !ok {
		return false
	}
	handler, err := manager.GetHandler(context.Background(), serverInboundTag)
	if err != nil {
		return false
	}
	getter, ok := handler.(proxy.GetInbound)
	if !ok {
		return false
	}
	users, ok := getter.GetInbound().(proxy.UserManager)
	if !ok {
		return false
	}
	var additions []*protocol.MemoryUser
	for email, user := range newUsers {
		if oldUsers[email] != nil {
			continue
		}
		memory, err := user.ToMemoryUser()
		if err != nil {
			return false
		}
		additions = append(additions, memory)
	}
	routes, ok := r.instance.GetFeature(routing.RouterType()).(routing.Router)
	if !ok || routes.AddRule(serial.ToTypedMessage(newRoutes), false) != nil {
		return false
	}
	// Install permissions before credentials. On any partial failure Apply
	// replaces the instance from the complete desired configuration.
	for _, user := range additions {
		if users.AddUser(context.Background(), user) != nil {
			return false
		}
	}
	return true
}

// Separate credentials and rules from everything requiring a listener restart.
// Work on clones: the last successfully applied configuration is immutable.
func serverConfigParts(config *core.Config) (*core.Config, map[string]*protocol.User, *router.Config, bool) {
	if config == nil || len(config.Inbound) != 1 || config.Inbound[0].Tag != serverInboundTag {
		return nil, nil, nil, false
	}
	base := proto.Clone(config).(*core.Config)
	settings, err := base.Inbound[0].ProxySettings.GetInstance()
	if err != nil {
		return nil, nil, nil, false
	}
	vl, ok := settings.(*vlessin.Config)
	if !ok {
		return nil, nil, nil, false
	}
	users := make(map[string]*protocol.User, len(vl.Users))
	for _, user := range vl.Users {
		if user.Email == "" || users[user.Email] != nil {
			return nil, nil, nil, false
		}
		users[user.Email] = user
	}
	vl.Users = nil
	base.Inbound[0].ProxySettings = serial.ToTypedMessage(vl)
	for i, app := range base.App {
		settings, err := app.GetInstance()
		if err != nil {
			return nil, nil, nil, false
		}
		if routes, ok := settings.(*router.Config); ok {
			fixed := proto.Clone(routes).(*router.Config)
			fixed.Rule = nil
			base.App[i] = serial.ToTypedMessage(fixed)
			return base, users, routes, true
		}
	}
	return nil, nil, nil, false
}

func containsMessages[T proto.Message](old, next []T) bool {
	// An empty list is unrestricted, so adding a condition would narrow access.
	if len(old) == 0 {
		return len(next) == 0
	}
	if len(next) == 0 {
		return true
	}
	for _, before := range old {
		found := false
		for _, after := range next {
			if proto.Equal(before, after) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func preservesRule(old, next *router.RoutingRule) bool {
	if !containsMessages(old.Domain, next.Domain) || !containsMessages(old.Ip, next.Ip) {
		return false
	}
	before, after := proto.Clone(old).(*router.RoutingRule), proto.Clone(next).(*router.RoutingRule)
	before.Domain, before.Ip, after.Domain, after.Ip = nil, nil, nil, nil
	return proto.Equal(before, after)
}
