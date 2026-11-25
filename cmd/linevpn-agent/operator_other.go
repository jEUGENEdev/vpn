//go:build !windows && !darwin

package main

import "errors"

func openDesktopOperator(string) (*desktopOperator, error) { return nil, nil }
func serveOperatorDialog(string) error                     { return errors.New("desktop dialog unavailable") }
