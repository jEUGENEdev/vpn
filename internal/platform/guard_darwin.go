package platform

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"syscall"
)

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
