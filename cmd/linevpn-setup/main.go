// linevpn-setup is the universal macOS installer launcher. Privileged work is
// requested explicitly through the standard macOS administrator dialog.
package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

func main() {
	executable, err := os.Executable()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	resources := filepath.Join(filepath.Dir(executable), "..", "Resources")
	command := exec.Command("/usr/bin/osascript", filepath.Join(resources, "installer.applescript"), resources)
	command.Stdout = os.Stdout
	command.Stderr = os.Stderr
	if err := command.Run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
