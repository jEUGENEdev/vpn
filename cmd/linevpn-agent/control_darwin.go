package main

import (
	"errors"
	"os"
	"os/exec"
)

func privilegedControlPath() (string, error) {
	if os.Geteuid() != 0 {
		return "", errors.New("для изменения настроек требуется системное подтверждение")
	}
	return "/var/lib/linevpn/control/session.json", nil
}
func confirmControl(description string) bool {
	script := `on run argv
 display dialog (item 1 of argv) with title "Сеть — изменение настроек" buttons {"Отмена", "Разрешить"} default button "Отмена" cancel button "Отмена" with icon caution
end run`
	return exec.Command("/usr/bin/osascript", "-e", script, description).Run() == nil
}
