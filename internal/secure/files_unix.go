//go:build !windows

package secure

import (
	"errors"
	"os"
)

func checkDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode().Perm()&0022 != 0 {
		return errors.New("secret directory must be a real directory not writable by other users")
	}
	// Traversal/read may be intentional for the public desktop UI token. Secrets
	// are protected individually; never chmod the shared data directory here.
	return nil
}

func protectFile(f *os.File) error { return f.Chmod(0600) }

func syncDirectory(path string) error {
	d, err := os.Open(path)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
