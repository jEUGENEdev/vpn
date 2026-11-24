//go:build !windows

package secure

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSaveRejectsWritableDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "shared")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0777); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "secret")
	if err := Save(path, []byte("secret")); err == nil {
		t.Fatal("published secret in a directory writable by others")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("failed save published a file")
	}
}

func TestSaveRestrictsLegacyFileAndPreservesPublicDirectory(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0711); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "secret")
	if err := os.WriteFile(path, []byte("old"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := Save(path, []byte("new")); err != nil {
		t.Fatal(err)
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0600 {
		t.Fatal(info.Mode())
	}
	info, _ = os.Stat(dir)
	if info.Mode().Perm() != 0711 {
		t.Fatal("broke desktop public token traversal")
	}
}
