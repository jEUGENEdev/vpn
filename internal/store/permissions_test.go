//go:build !windows

package store

import (
	"os"
	"path/filepath"
	"testing"
)

func TestOpenRestrictsExistingDatabase(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	st, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	st.Close()
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	st, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0600 {
		t.Fatalf("existing database retains %v permissions", info.Mode())
	}
}
