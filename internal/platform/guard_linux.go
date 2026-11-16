//go:build linux && !android

package platform

import "errors"

func Guard(name string) error {
	return errors.New("desktop client supports macOS and Windows; Linux is server/test only")
}
func ConfigureDNS() error             { return nil }
func DropPrivileges(dir string) error { return nil }
