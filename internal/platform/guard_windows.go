package platform

import (
	"crypto/sha256"
	"errors"
	"github.com/tailscale/wf"
	"golang.org/x/sys/windows"
	"os/exec"
	"syscall"
	"unsafe"
)

// Legacy IDs are retained only for cleanup. New sessions never install a deny.
var provider = wf.ProviderID(guid("linevpn-provider"))
var sublayer = wf.SublayerID(guid("linevpn-sublayer"))

func guid(s string) windows.GUID {
	v := sha256.Sum256([]byte(s))
	return *(*windows.GUID)(unsafe.Pointer(&v[0]))
}
func ConfigureDNS(dir string) error   { _, e := exec.Command("ipconfig", "/flushdns").Output(); return e }
func DropPrivileges(dir string) error { return nil }
func Recover(dir string) error {
	s, e := wf.New(nil)
	if e != nil {
		return e
	}
	defer s.Close()
	rules, e := s.Rules()
	if e != nil {
		return e
	}
	var failures []error
	for _, r := range rules {
		if r.Provider == provider {
			if e = s.DeleteRule(r.ID); e != nil && !errors.Is(e, syscall.Errno(windows.FWP_E_FILTER_NOT_FOUND)) {
				failures = append(failures, e)
			}
		}
	}
	if e = s.DeleteSublayer(sublayer); e != nil && !errors.Is(e, windows.ERROR_NOT_FOUND) && !errors.Is(e, syscall.Errno(windows.FWP_E_SUBLAYER_NOT_FOUND)) {
		failures = append(failures, e)
	}
	if e = s.DeleteProvider(provider); e != nil && !errors.Is(e, windows.ERROR_NOT_FOUND) && !errors.Is(e, syscall.Errno(windows.FWP_E_PROVIDER_NOT_FOUND)) {
		failures = append(failures, e)
	}
	return errors.Join(append(failures, ConfigureDNS(dir))...)
}
