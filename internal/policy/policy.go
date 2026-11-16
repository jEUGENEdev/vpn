// Package policy contains the one routing decision used by clients and server.
package policy

import (
	"errors"
	"net/netip"
	"sort"
	"strings"

	"golang.org/x/net/idna"
	"golang.org/x/net/publicsuffix"
)

var ErrTarget = errors.New("укажите домен или IP, без схемы, порта, пути и маски")

// Normalize deliberately rejects URLs, CIDRs, wildcards and ambiguous IPv4 forms.
func Normalize(s string) (string, error) {
	s = strings.TrimSpace(s)
	if ip, err := netip.ParseAddr(s); err == nil {
		if ip.Zone() != "" {
			return "", ErrTarget
		}
		return ip.Unmap().String(), nil
	}
	s = strings.TrimSuffix(strings.ToLower(s), ".")
	if s == "" || strings.ContainsAny(s, ":/\\@*?#%[] \t\r\n") {
		return "", ErrTarget
	}
	ascii, err := idna.Lookup.ToASCII(s)
	if err != nil || len(ascii) > 253 {
		return "", ErrTarget
	}
	labels := strings.Split(ascii, ".")
	if len(labels) < 2 {
		return "", ErrTarget
	}
	numeric := true
	for _, l := range labels {
		if l == "" || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
			return "", ErrTarget
		}
		for _, c := range l {
			if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-') {
				return "", ErrTarget
			}
			if c < '0' || c > '9' {
				numeric = false
			}
		}
	}
	if numeric {
		return "", ErrTarget
	}
	suffix, _ := publicsuffix.PublicSuffix(ascii)
	if suffix == ascii {
		return "", errors.New("нельзя разрешить целую публичную зону")
	}
	return ascii, nil
}

func Matches(rule, target string) bool {
	if rule == target {
		return true
	}
	if _, err := netip.ParseAddr(rule); err == nil {
		return false
	}
	if _, err := netip.ParseAddr(target); err == nil {
		return false
	}
	return strings.HasSuffix(target, "."+rule)
}

func Approved(rules []string, target string) bool {
	target, err := Normalize(target)
	if err != nil {
		return false
	}
	for _, r := range rules {
		if Matches(r, target) {
			return true
		}
	}
	return false
}

func Clean(rules []string) ([]string, error) {
	seen := map[string]bool{}
	for _, s := range rules {
		n, e := Normalize(s)
		if e != nil {
			return nil, e
		}
		seen[n] = true
	}
	out := make([]string, 0, len(seen))
	for r := range seen {
		out = append(out, r)
	}
	sort.Strings(out)
	return out, nil
}

func Group(target string) string {
	if root, err := publicsuffix.EffectiveTLDPlusOne(target); err == nil {
		return root
	}
	return target
}

type Route string

const (
	Direct Route = "direct"
	VPN    Route = "vpn"
	Block  Route = "blocked"
)

func Decide(rules []string, target string, ready bool) Route {
	if _, err := Normalize(target); err != nil {
		return Block
	}
	if !Approved(rules, target) {
		return Direct
	}
	if !ready {
		return Block
	}
	return VPN
}

// Public prevents server egress into private networks, metadata, multicast and
// transition prefixes. Rechecked on the actual resolved IP before every dial.
func Public(ip netip.Addr) bool {
	ip = ip.Unmap()
	if !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
		return false
	}
	for _, s := range []string{"0.0.0.0/8", "100.64.0.0/10", "192.0.0.0/24", "192.0.2.0/24", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4", "::/96", "64:ff9b::/96", "64:ff9b:1::/48", "100::/64", "2001::/23", "2002::/16"} {
		if netip.MustParsePrefix(s).Contains(ip) {
			return false
		}
	}
	return true
}
