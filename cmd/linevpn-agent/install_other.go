//go:build !windows

package main

import "errors"

func cleanInstallation(bool) error {
	return errors.New("use the macOS installer to remove the application")
}
