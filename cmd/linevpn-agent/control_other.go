//go:build !windows && !darwin

package main

import "errors"

func privilegedControlPath() (string, error) {
	return "", errors.New("desktop control is supported on Windows and macOS")
}
func confirmControl(string) bool { return false }
