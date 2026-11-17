package transport

import (
	"context"
	"strings"

	"github.com/xtls/xray-core/app/router"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/inbound"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/proxy"
	vless "github.com/xtls/xray-core/proxy/vless/inbound"
	"google.golang.org/protobuf/proto"
)

type serverAccess struct {
	static *core.Config
	users  map[string]*protocol.User
	router *router.Config
}

// Recognize our single VLESS listener, keeping every other setting in static.
// Removing access still restarts the instance to cancel already accepted TCP
// and UDP streams; Xray's RemoveUser alone only prevents new authentications.
func splitServerAccess(config *core.Config) *serverAccess {
	if config == nil || len(config.Inbound) != 1 || config.Inbound[0].Tag != "linevpn" {
		return nil
	}
	static := proto.Clone(config).(*core.Config)
	settings, err := static.Inbound[0].ProxySettings.GetInstance()
	if err != nil {
		return nil
	}
	in, ok := settings.(*vless.Config)
	if !ok {
		return nil
	}
	access := &serverAccess{static: static, users: map[string]*protocol.User{}}
	for _, user := range in.Users {
		email := strings.ToLower(user.Email)
		if email == "" || access.users[email] != nil {
			return nil
		}
		access.users[email] = user
	}
	in.Users = nil
	static.Inbound[0].ProxySettings = serial.ToTypedMessage(in)
	for i, app := range static.App {
		settings, err := app.GetInstance()
		if err != nil {
			return nil
		}
		if routes, ok := settings.(*router.Config); ok {
			if access.router != nil || routes.Script != "" || len(routes.BalancingRule) != 0 {
				return nil
			}
			for _, rule := range routes.Rule {
				if rule.GetTag() != "allowed" || len(rule.UserEmail) != 1 {
					return nil
				}
			}
			access.router = proto.Clone(routes).(*router.Config)
			routes.Rule = nil
			static.App[i] = serial.ToTypedMessage(routes)
		}
	}
	if access.router == nil {
		return nil
	}
	return access
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

// Called with r.mu held. Add devices and widen allowlists without tearing down
// other devices' XHTTP connections. Any unsupported change uses a full restart.
func (r *Runtime) addServerAccess(config *core.Config) bool {
	old, next := splitServerAccess(r.config), splitServerAccess(config)
	if old == nil || next == nil || !proto.Equal(old.static, next.static) {
		return false
	}
	for email, user := range old.users {
		if !proto.Equal(user, next.users[email]) {
			return false
		}
	}
	for _, before := range old.router.Rule {
		preserved := false
		for _, after := range next.router.Rule {
			if preservesRule(before, after) {
				preserved = true
				break
			}
		}
		if !preserved {
			return false
		}
	}
	manager, ok := r.instance.GetFeature(inbound.ManagerType()).(inbound.Manager)
	if !ok {
		return false
	}
	handler, err := manager.GetHandler(context.Background(), "linevpn")
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
	routes, ok := r.instance.GetFeature(routing.RouterType()).(routing.Router)
	if !ok {
		return false
	}
	// Install user-scoped permissions first: a newly authenticated user must
	// never race with a still-missing allow rule. Existing rules only widen.
	if err := routes.AddRule(serial.ToTypedMessage(next.router), false); err != nil {
		return false
	}
	for email, user := range next.users {
		if old.users[email] != nil {
			continue
		}
		memory, err := user.ToMemoryUser()
		if err != nil || users.AddUser(context.Background(), memory) != nil {
			// Apply will rebuild from the complete config after a partial update.
			return false
		}
	}
	r.config = config
	return true
}
