package transport

import (
	"net/netip"
	"sort"
	"time"

	"github.com/jEUGENEdev/vpn/internal/model"
	"github.com/jEUGENEdev/vpn/internal/policy"
	"github.com/jEUGENEdev/vpn/internal/store"
)

type ServerOptions struct {
	BlockedIPs []string `json:"blocked_ips,omitempty"`
	Listen     string   `json:"listen"`
	Port       int      `json:"port"`
	PrivateKey string   `json:"private_key"`
	PublicKey  string   `json:"public_key"`
	SNI        string   `json:"sni"`
	Target     string   `json:"target"`
	ShortID    string   `json:"short_id"`
	Path       string   `json:"path"`
}

func ServerConfig(s store.State, o ServerOptions, now time.Time) obj {
	clients := []obj{}
	rules := []obj{}
	deviceIDs := make([]string, 0, len(s.Devices))
	for id := range s.Devices {
		deviceIDs = append(deviceIDs, id)
	}
	sort.Strings(deviceIDs)
	for _, id := range deviceIDs {
		d := s.Devices[id]
		a, ok := s.Accounts[d.AccountID]
		if !ok || a.Status != "active" || d.Revoked || !now.Before(d.Expires) {
			continue
		}
		clients = append(clients, obj{"id": d.Secret, "email": d.ID})
		if d.AppSecret != "" {
			clients = append(clients, obj{"id": d.AppSecret, "email": d.ID + ":apps"})
			rules = append(rules, obj{"type": "field", "user": []string{d.ID + ":apps"}, "outboundTag": "allowed"})
		}
		domains := []string{}
		ips := []string{}
		for _, r := range a.Rules {
			if _, e := netip.ParseAddr(r); e == nil {
				ips = append(ips, r)
			} else {
				domains = append(domains, "domain:"+r)
			}
		}
		if len(domains) > 0 {
			rules = append(rules, obj{"type": "field", "user": []string{d.ID}, "domain": domains, "outboundTag": "allowed"})
		}
		if len(ips) > 0 {
			rules = append(rules, obj{"type": "field", "user": []string{d.ID}, "ip": ips, "outboundTag": "allowed"})
		}
	}
	// Blackhole is also the default outbound. No permissive catch-all exists.
	return obj{
		"log": obj{"loglevel": "none"},
		"inbounds": []obj{{
			"tag":      serverInboundTag,
			"listen":   o.Listen,
			"port":     o.Port,
			"protocol": "vless",
			"settings": obj{"clients": clients, "decryption": "none"},
			"streamSettings": obj{
				"network":  "xhttp",
				"security": "reality",
				"realitySettings": obj{
					"show":        false,
					"dest":        o.Target,
					"serverNames": []string{o.SNI},
					"privateKey":  o.PrivateKey,
					"shortIds":    []string{o.ShortID},
				},
				"xhttpSettings": obj{"path": o.Path, "mode": "auto"},
			},
		}},
		"outbounds": []obj{
			{"tag": "deny", "protocol": "blackhole"},
			{
				"tag":            "allowed",
				"protocol":       "freedom",
				"settings":       obj{"finalRules": []obj{{"action": "block", "ip": append(policy.NonPublicCIDRs(), o.BlockedIPs...)}}},
				"streamSettings": obj{"sockopt": obj{"domainStrategy": "UseIP"}},
			},
		},
		"routing": obj{"domainStrategy": "AsIs", "rules": rules},
	}
}

func ClientConfig(p model.Profile) obj {
	return obj{
		"log": obj{"loglevel": "none"},
		"outbounds": []obj{{
			"tag":      "vpn",
			"protocol": "vless",
			"settings": obj{"vnext": []obj{{
				"address": p.Server,
				"port":    p.Port,
				"users":   []obj{{"id": p.UUID, "encryption": "none"}},
			}}},
			"streamSettings": obj{
				"network":  "xhttp",
				"security": "reality",
				"realitySettings": obj{
					"serverName":  p.SNI,
					"fingerprint": "chrome",
					"publicKey":   p.PublicKey,
					"shortId":     p.ShortID,
				},
				"xhttpSettings": obj{"path": p.Path, "mode": "auto"},
			},
		}},
	}
}
