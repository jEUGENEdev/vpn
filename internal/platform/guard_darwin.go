package platform

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

func Guard(name string) error {
	if os.Geteuid() != 0 {
		return errors.New("нужна установленная фоновая служба")
	}
	if name != "" && !strings.HasPrefix(name, "utun") {
		return errors.New("invalid interface")
	}
	hook, e := exec.Command("/sbin/pfctl", "-sr").Output()
	if e != nil || !strings.Contains(string(hook), `anchor "linevpn"`) {
		if b, err := exec.Command("/sbin/pfctl", "-f", "/etc/pf.conf").CombinedOutput(); err != nil {
			return fmt.Errorf("PF config: %s: %w", b, err)
		}
	}
	rules := "pass out quick on lo0 all\npass out quick proto { tcp udp } from any to any user _linevpn\npass out quick inet proto udp from any port 68 to 255.255.255.255 port 67\npass out quick inet6 proto icmp6 icmp6-type { routersol, neighbrsol, neighbradv }\n"
	if name != "" {
		rules += "pass out quick on " + name + " all\n"
	}
	rules += "block drop out quick all\n"
	cmd := exec.Command("/sbin/pfctl", "-a", "linevpn", "-f", "-")
	cmd.Stdin = strings.NewReader(rules)
	if b, e := cmd.CombinedOutput(); e != nil {
		return fmt.Errorf("PF: %s: %w", b, e)
	}
	exec.Command("/sbin/pfctl", "-E").Run()
	info, e := exec.Command("/sbin/pfctl", "-s", "info").CombinedOutput()
	if e != nil || !strings.Contains(string(info), "Status: Enabled") {
		return errors.New("PF is not enabled")
	}
	if name == "" {
		if e := exec.Command("/sbin/pfctl", "-F", "states").Run(); e != nil {
			return e
		}
	}
	return nil
}
func ConfigureDNS() error {
	b, e := exec.Command("/usr/sbin/networksetup", "-listallnetworkservices").Output()
	if e != nil {
		return e
	}
	backup := map[string][]string{}
	path := "/var/lib/linevpn/dns-backup.json"
	if b, e := os.ReadFile(path); e == nil {
		json.Unmarshal(b, &backup)
	}
	for i, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		if i == 0 || strings.HasPrefix(line, "*") {
			continue
		}
		if _, ok := backup[line]; !ok {
			old, e := exec.Command("/usr/sbin/networksetup", "-getdnsservers", line).Output()
			if e != nil {
				return e
			}
			values := strings.Fields(string(old))
			if strings.Contains(string(old), "aren't any") {
				values = []string{"Empty"}
			}
			backup[line] = values
			raw, _ := json.Marshal(backup)
			if e = os.WriteFile(path, raw, 0600); e != nil {
				return e
			}
		}
		if b, e := exec.Command("/usr/sbin/networksetup", "-setdnsservers", line, "172.29.255.2").CombinedOutput(); e != nil {
			return fmt.Errorf("DNS: %s: %w", b, e)
		}
	}
	exec.Command("/usr/bin/dscacheutil", "-flushcache").Run()
	return nil
}
func DropPrivileges(dir string) error {
	u, e := user.Lookup("_linevpn")
	if e != nil {
		return e
	}
	uid, _ := strconv.Atoi(u.Uid)
	gid, _ := strconv.Atoi(u.Gid)
	if uid == 0 {
		return errors.New("invalid service UID")
	}
	if e = filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		return os.Chown(path, uid, gid)
	}); e != nil {
		return e
	}
	if e = syscall.Setgroups([]int{gid}); e != nil {
		return e
	}
	if e = syscall.Setgid(gid); e != nil {
		return e
	}
	return syscall.Setuid(uid)
}
