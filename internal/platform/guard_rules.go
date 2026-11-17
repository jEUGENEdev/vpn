package platform

import (
	"errors"
	"strconv"
	"strings"
)

// Keep PF rules pure so both IPv4/IPv6 deny coverage and interface validation
// can be checked without changing the host firewall.
func guardRules(name string) (string, error) {
	if name != "" {
		if !strings.HasPrefix(name, "utun") {
			return "", errors.New("invalid tunnel interface")
		}
		if _, err := strconv.ParseUint(strings.TrimPrefix(name, "utun"), 10, 32); err != nil {
			return "", errors.New("invalid tunnel interface")
		}
	}
	rules := "pass out quick on lo0 all flags any no state\npass out quick proto { tcp udp } from any to any user _linevpn keep state (if-bound)\npass out quick inet proto udp from any port 68 to 255.255.255.255 port 67\npass out quick inet6 proto udp from any port 546 to ff02::1:2 port 547\npass out quick inet6 proto icmp6 icmp6-type { routersol, neighbrsol, neighbradv }\n"
	if name != "" {
		rules += "pass out quick on " + name + " all keep state (if-bound)\n"
	}
	return rules + "block drop out quick all\n", nil
}
