package main

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestRemoveOwnedDirectory(t *testing.T) {
	// macOS exposes /var through a system symlink. Resolve the fixture root;
	// production callers use canonical system/profile paths on Windows.
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	own, other := filepath.Join(root, "LineVPN"), filepath.Join(root, "another-app")
	for _, path := range []string{own, other} {
		if err := os.MkdirAll(path, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(path, "credentials"), []byte("fixture"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := removeOwnedDirectory(own); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(own); !os.IsNotExist(err) {
		t.Fatal("old state survived")
	}
	if err := removeOwnedDirectory(own); err != nil {
		t.Fatal("repeat removal", err)
	}
	if _, err := os.Stat(filepath.Join(other, "credentials")); err != nil {
		t.Fatal("unrelated state changed", err)
	}
	if runtime.GOOS == "windows" {
		return
	} // Symlinks require a separate Windows privilege.
	if err := os.Symlink(other, own); err != nil {
		t.Fatal(err)
	}
	if err := removeOwnedDirectory(own); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(other, "credentials")); err != nil {
		t.Fatal("followed the final symlink", err)
	}
	if err := os.Mkdir(filepath.Join(other, "LineVPN"), 0700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "linked-profile")
	if err := os.Symlink(other, link); err != nil {
		t.Fatal(err)
	}
	if err := removeOwnedDirectory(filepath.Join(link, "LineVPN")); err == nil {
		t.Fatal("followed parent symlink")
	}
	if _, err := os.Stat(filepath.Join(other, "LineVPN")); err != nil {
		t.Fatal("removed foreign directory", err)
	}
}
