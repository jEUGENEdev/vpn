//go:build !windows

package main

import (
	"context"
	"errors"
	"os"
)

func runService(run func(context.Context) error) error {
	return errors.New("service flag is Windows only")
}
func tokenPermissions(dir, path string) error {
	if e := os.Chmod(dir, 0711); e != nil {
		return e
	}
	return os.Chmod(path, 0644)
}
