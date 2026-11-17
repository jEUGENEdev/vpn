package platform

import (
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
	hook, e = exec.Command("/sbin/pfctl", "-sr").Output()
	if e != nil || !strings.Contains(string(hook), `anchor "linevpn"`) {
		return errors.New("LineVPN PF anchor missing; reinstall the client")
	}
	rules, e := guardRules(name)
	if e != nil {
		return e
	}
	cmd := exec.Command("/sbin/pfctl", "-a", "linevpn", "-f", "-")
	cmd.Stdin = strings.NewReader(rules)
	if b, e := cmd.CombinedOutput(); e != nil {
		return fmt.Errorf("PF: %s: %w", b, e)
	}
	info, e := exec.Command("/sbin/pfctl", "-s", "info").CombinedOutput()
	if e == nil && !strings.Contains(string(info), "Status: Enabled") {
		if b, err := exec.Command("/sbin/pfctl", "-e").CombinedOutput(); err != nil {
			return fmt.Errorf("PF enable: %s: %w", b, err)
		}
		info, e = exec.Command("/sbin/pfctl", "-s", "info").CombinedOutput()
	}
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

func Recover(dir string) error {
	if os.Geteuid() != 0 {
		return errors.New("для восстановления сети нужны права администратора")
	}
	// Independent cleanup: a broken DNS backup must not preserve a PF deny.
	var failures []error
	if b, err := exec.Command("/sbin/pfctl", "-a", "linevpn", "-F", "rules").CombinedOutput(); err != nil {
		failures = append(failures, fmt.Errorf("PF recovery: %s: %w", b, err))
	}
	failures = append(failures, systemDNS(dir).restore())
	return errors.Join(failures...)
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
