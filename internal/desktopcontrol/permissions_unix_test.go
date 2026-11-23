//go:build !windows

package desktopcontrol

import (
	"os"
	"path/filepath"
	"testing"
)

func TestControlSessionNotReadableByOrdinaryUsers(t *testing.T) {
	dir := t.TempDir()
	channel, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer channel.Listener.Close()
	for _, p := range []string{"control", "control/session.json"} {
		info, err := os.Stat(filepath.Join(dir, p))
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm()&0077 != 0 {
			t.Fatal("administrative credential exposed", p, info.Mode())
		}
	}
}
