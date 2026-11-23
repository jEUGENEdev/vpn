package platform

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"github.com/tailscale/wf"
	"golang.org/x/sys/windows"
	"net"
	"os"
	"os/exec"
	"syscall"
	"unsafe"
)

// These stable IDs keep the deny policy installed across worker restarts.
var provider = wf.ProviderID(guid("linevpn-provider"))
var sublayer = wf.SublayerID(guid("linevpn-sublayer"))

func guid(s string) windows.GUID {
	v := sha256.Sum256([]byte(s))
	return *(*windows.GUID)(unsafe.Pointer(&v[0]))
}
func Guard(name string) error {
	s, e := wf.New(&wf.Options{Name: "Сеть — защита подключения", Dynamic: false})
	if e != nil {
		return e
	}
	defer s.Close()
	providers, e := s.Providers()
	if e != nil {
		return e
	}
	found := false
	for _, p := range providers {
		if p.ID == provider {
			found = true
		}
	}
	if !found {
		if e = s.AddProvider(&wf.Provider{ID: provider, Name: "Сеть", Persistent: true}); e != nil {
			return e
		}
	}
	subs, e := s.Sublayers(provider)
	if e != nil {
		return e
	}
	found = false
	for _, sl := range subs {
		if sl.ID == sublayer {
			found = true
		}
	}
	if !found {
		if e = s.AddSublayer(&wf.Sublayer{ID: sublayer, Name: "Сеть", Provider: provider, Persistent: true, Weight: 65535}); e != nil {
			return e
		}
	}
	existing, e := s.Rules()
	if e != nil {
		return e
	}
	ids := map[wf.RuleID]bool{}
	for _, r := range existing {
		ids[r.ID] = true
	}
	add := func(key string, layer wf.LayerID, weight uint64, action wf.Action, conditions ...*wf.Match) error {
		id := wf.RuleID(guid(key + layer.String()))
		if ids[id] {
			return nil
		}
		return s.AddRule(&wf.Rule{ID: id, Name: "Сеть " + key, Layer: layer, Sublayer: sublayer, Provider: provider, Persistent: true, Weight: weight, Action: action, HardAction: action == wf.ActionPermit, Conditions: conditions})
	}
	exe, e := os.Executable()
	if e != nil {
		return e
	}
	app, e := wf.AppID(exe)
	if e != nil {
		return e
	}
	for _, layer := range []wf.LayerID{wf.LayerALEAuthConnectV4, wf.LayerALEAuthConnectV6} {
		if e = add("deny", layer, 1, wf.ActionBlock); e != nil {
			return e
		}
		if e = add("agent", layer, 100, wf.ActionPermit, &wf.Match{Field: wf.FieldALEAppID, Op: wf.MatchTypeEqual, Value: app}); e != nil {
			return e
		}
		if e = add("loopback", layer, 90, wf.ActionPermit, &wf.Match{Field: wf.FieldFlags, Op: wf.MatchTypeFlagsAllSet, Value: wf.ConditionFlagIsLoopback}); e != nil {
			return e
		}
	}
	// Delete only previous tunnel permits. The persistent deny remains installed.
	for _, r := range existing {
		if r.Provider == provider && (r.Name == "LineVPN tunnel" || r.Name == "Сеть tunnel") {
			if e = s.DeleteRule(r.ID); e != nil {
				return e
			}
			delete(ids, r.ID)
		}
	}
	if name == "" {
		return nil
	}
	iface, e := net.InterfaceByName(name)
	if e != nil {
		return e
	}
	var luid uint64
	proc := windows.NewLazySystemDLL("iphlpapi.dll").NewProc("ConvertInterfaceIndexToLuid")
	code, _, _ := proc.Call(uintptr(iface.Index), uintptr(unsafe.Pointer(&luid)))
	if code != 0 {
		return fmt.Errorf("interface LUID: %d", code)
	}
	for _, layer := range []wf.LayerID{wf.LayerALEAuthConnectV4, wf.LayerALEAuthConnectV6} {
		if e = add("tunnel", layer, 80, wf.ActionPermit, &wf.Match{Field: wf.FieldIPLocalInterface, Op: wf.MatchTypeEqual, Value: luid}); e != nil {
			return e
		}
	}
	if e = add("dhcp4", wf.LayerALEAuthConnectV4, 70, wf.ActionPermit, &wf.Match{Field: wf.FieldIPProtocol, Op: wf.MatchTypeEqual, Value: wf.IPProtoUDP}, &wf.Match{Field: wf.FieldIPLocalPort, Op: wf.MatchTypeEqual, Value: uint16(68)}, &wf.Match{Field: wf.FieldIPRemotePort, Op: wf.MatchTypeEqual, Value: uint16(67)}); e != nil {
		return e
	}
	return nil
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
