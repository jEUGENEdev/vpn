package main

import (
	"fmt"
	"os"
	"path/filepath"
)

// Remove only the named application directory. A user-controlled parent link
// must never redirect an elevated uninstaller to another application's data.
func removeOwnedDirectory(path string) error {
	if _, err := os.Lstat(path); os.IsNotExist(err) {
		return nil
	} else if err != nil {
		return err
	}
	for parent := filepath.Dir(path); ; parent = filepath.Dir(parent) {
		info, err := os.Lstat(parent)
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("refusing linked parent: %s", parent)
		}
		if filepath.Dir(parent) == parent {
			break
		}
	}
	return os.RemoveAll(path)
}
