package platform

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/jEUGENEdev/vpn/internal/secure"
)

const tunnelDNS = "172.29.255.2"

// Keep restoration independently testable without changing the test host's DNS.
type dnsSettings struct {
	path string
	run  func(string, ...string) ([]byte, error)
}

func systemDNS(dir string) dnsSettings {
	return dnsSettings{filepath.Join(dir, "dns-backup.json"), func(name string, args ...string) ([]byte, error) {
		return exec.Command(name, args...).CombinedOutput()
	}}
}

func (d dnsSettings) services() ([]string, error) {
	b, err := d.run("/usr/sbin/networksetup", "-listallnetworkservices")
	if err != nil {
		return nil, fmt.Errorf("list DNS services: %s: %w", b, err)
	}
	var names []string
	for i, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		line = strings.TrimSpace(line)
		if i > 0 && line != "" {
			names = append(names, strings.TrimPrefix(line, "*"))
		}
	}
	return names, nil
}

func dnsValues(raw []byte) ([]string, error) {
	if strings.HasPrefix(strings.TrimSpace(string(raw)), "There aren't any DNS Servers set on ") {
		return []string{"Empty"}, nil
	}
	values := strings.Fields(string(raw))
	if len(values) == 0 {
		return nil, fmt.Errorf("empty DNS settings")
	}
	for _, value := range values {
		if _, err := netip.ParseAddr(value); err != nil {
			return nil, fmt.Errorf("invalid DNS address %q", value)
		}
	}
	return values, nil
}

func (d dnsSettings) current(name string) ([]string, error) {
	b, err := d.run("/usr/sbin/networksetup", "-getdnsservers", name)
	if err != nil {
		return nil, fmt.Errorf("read DNS for %s: %w", name, err)
	}
	return dnsValues(b)
}

func ownedDNS(values []string) bool {
	for _, value := range values {
		if value == tunnelDNS {
			return true
		}
	}
	return false
}

func (d dnsSettings) backup() (map[string][]string, error) {
	backup := map[string][]string{}
	raw, err := os.ReadFile(d.path)
	if os.IsNotExist(err) {
		return backup, nil
	}
	if err != nil {
		return nil, err
	}
	if err = json.Unmarshal(raw, &backup); err != nil || backup == nil {
		return nil, fmt.Errorf("invalid DNS backup: %s", d.path)
	}
	for name, values := range backup {
		if name == "" || len(values) == 0 || ownedDNS(values) {
			return nil, fmt.Errorf("invalid DNS backup for %q", name)
		}
		if len(values) == 1 && values[0] == "Empty" {
			continue
		}
		if _, err = dnsValues([]byte(strings.Join(values, "\n"))); err != nil {
			return nil, err
		}
	}
	return backup, nil
}

func (d dnsSettings) set(name string, values []string) error {
	b, err := d.run("/usr/sbin/networksetup", append([]string{"-setdnsservers", name}, values...)...)
	if err != nil {
		return fmt.Errorf("set DNS for %s: %s: %w", name, b, err)
	}
	return nil
}

func (d dnsSettings) flush() error {
	if _, err := d.run("/usr/bin/dscacheutil", "-flushcache"); err != nil {
		return err
	}
	_, err := d.run("/usr/bin/killall", "-HUP", "mDNSResponder")
	return err
}

func (d dnsSettings) configure() error {
	backup, err := d.backup()
	if err != nil {
		return err
	}
	names, err := d.services()
	if err != nil {
		return err
	}
	for _, name := range names {
		values, err := d.current(name)
		if err != nil {
			return err
		}
		if !ownedDNS(values) {
			// A new enable captures today's settings, including user edits.
			backup[name] = values
			raw, _ := json.Marshal(backup)
			if err = secure.Save(d.path, raw); err != nil {
				return err
			}
		} else if _, ok := backup[name]; !ok {
			return fmt.Errorf("нет исходных DNS для %s; восстановите DNS в настройках сети", name)
		}
		if err = d.set(name, []string{tunnelDNS}); err != nil {
			return err
		}
	}
	return d.flush()
}

func (d dnsSettings) restore() error {
	backup, backupErr := d.backup()
	if backupErr != nil {
		// An old/corrupt/missing backup must never strand a physical NIC on
		// tunnel DNS. Preserve the file, remove only our address, use DHCP if empty.
		log.Printf("DNS backup unavailable; restoring owned settings to DHCP: %v", backupErr)
		backup = map[string][]string{}
	}
	names, err := d.services()
	if err != nil {
		return err
	}
	var failures []error
	for _, name := range names {
		values, err := d.current(name)
		if err != nil {
			failures = append(failures, err)
			continue
		}
		if !ownedDNS(values) {
			continue
		}
		previous, ok := backup[name]
		if !ok || len(values) > 1 {
			previous = nil
			for _, value := range values {
				if value != tunnelDNS {
					previous = append(previous, value)
				}
			}
			if len(previous) == 0 {
				previous = []string{"Empty"}
			}
		}
		if err = d.set(name, previous); err != nil {
			failures = append(failures, err)
		}
	}
	failures = append(failures, d.flush())
	if err = errors.Join(failures...); err != nil {
		return err
	}
	if backupErr == nil {
		if err = os.Remove(d.path); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	return nil
}
