package platform

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

type dnsMachine struct {
	values  map[string][]string
	failSet string
	flushes int
}

func (m *dnsMachine) run(command string, args ...string) ([]byte, error) {
	if command == "/usr/bin/dscacheutil" {
		m.flushes++
		return nil, nil
	}
	if command == "/usr/bin/killall" {
		return nil, nil
	}
	switch args[0] {
	case "-listallnetworkservices":
		// Disabled network services also need their DNS restored.
		return []byte("An asterisk denotes a disabled network service.\nWi-Fi\n*USB Ethernet\n"), nil
	case "-getdnsservers":
		values := m.values[args[1]]
		if len(values) == 1 && values[0] == "Empty" {
			return []byte("There aren't any DNS Servers set on " + args[1] + "."), nil
		}
		return []byte(strings.Join(values, "\n")), nil
	case "-setdnsservers":
		if m.failSet == args[1] {
			return nil, errors.New("networksetup failed")
		}
		m.values[args[1]] = append([]string{}, args[2:]...)
		return nil, nil
	}
	return nil, errors.New("unexpected command")
}

func TestDNSRestoresDHCPAndCustomServersAcrossPowerCycles(t *testing.T) {
	m := &dnsMachine{values: map[string][]string{"Wi-Fi": {"Empty"}, "USB Ethernet": {"9.9.9.9", "2620:fe::fe"}}}
	d := dnsSettings{filepath.Join(t.TempDir(), "dns-backup.json"), m.run}
	for cycle := 0; cycle < 2; cycle++ {
		wifi := append([]string{}, m.values["Wi-Fi"]...)
		if err := d.configure(); err != nil {
			t.Fatal(err)
		}
		// Restarting an enabled service must not save the synthetic DNS as old DNS.
		if err := d.configure(); err != nil {
			t.Fatal(err)
		}
		if err := d.restore(); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(m.values["Wi-Fi"], wifi) || !reflect.DeepEqual(m.values["USB Ethernet"], []string{"9.9.9.9", "2620:fe::fe"}) {
			t.Fatal(m.values)
		}
		if _, err := os.Stat(d.path); !os.IsNotExist(err) {
			t.Fatal("restored backup was retained", err)
		}
		// A user's new DNS while off must be captured on the next enable.
		m.values["Wi-Fi"] = []string{"8.8.8.8"}
	}
	if err := d.restore(); err != nil {
		t.Fatal("repeated recovery failed", err)
	}
	if m.flushes != 7 {
		t.Fatal("OS DNS caches not flushed", m.flushes)
	}
}

func TestDNSFailureRetainsBackupForRetryAndUserChanges(t *testing.T) {
	m := &dnsMachine{values: map[string][]string{"Wi-Fi": {"Empty"}, "USB Ethernet": {"9.9.9.9"}}}
	d := dnsSettings{filepath.Join(t.TempDir(), "dns-backup.json"), m.run}
	if err := d.configure(); err != nil {
		t.Fatal(err)
	}
	m.failSet = "USB Ethernet"
	if err := d.restore(); err == nil {
		t.Fatal("partial restoration falsely succeeded")
	}
	if _, err := os.Stat(d.path); err != nil {
		t.Fatal("lost recovery data", err)
	}
	// Preserve an explicit user edit between partial recovery attempts.
	m.values["Wi-Fi"] = []string{"1.0.0.1"}
	m.failSet = ""
	if err := d.restore(); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(m.values["Wi-Fi"], []string{"1.0.0.1"}) {
		t.Fatal("clobbered user DNS")
	}
}

func TestDNSOrphanAndCorruptBackupRestoreOnlyOwnedSettings(t *testing.T) {
	for _, raw := range []string{"", "broken JSON", `{"Wi-Fi":["172.29.255.2"]}`} {
		t.Run(raw, func(t *testing.T) {
			m := &dnsMachine{values: map[string][]string{"Wi-Fi": {tunnelDNS}, "USB Ethernet": {"9.9.9.9"}}}
			d := dnsSettings{filepath.Join(t.TempDir(), "dns-backup.json"), m.run}
			if raw != "" {
				os.WriteFile(d.path, []byte(raw), 0600)
			}
			if err := d.restore(); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(m.values["Wi-Fi"], []string{"Empty"}) {
				t.Fatal("orphan DNS retained", m.values)
			}
			if !reflect.DeepEqual(m.values["USB Ethernet"], []string{"9.9.9.9"}) {
				t.Fatal("user DNS overwritten")
			}
		})
	}
}

func TestDNSRecoveryContinuesAfterFirstInterfaceFailure(t *testing.T) {
	m := &dnsMachine{values: map[string][]string{"Wi-Fi": {tunnelDNS}, "USB Ethernet": {tunnelDNS, "9.9.9.9"}}, failSet: "Wi-Fi"}
	d := dnsSettings{filepath.Join(t.TempDir(), "dns-backup.json"), m.run}
	if err := d.restore(); err == nil {
		t.Fatal("failure hidden")
	}
	if !reflect.DeepEqual(m.values["USB Ethernet"], []string{"9.9.9.9"}) {
		t.Fatal("later interface not repaired", m.values)
	}
}

func TestDNSRecoveryPreservesAddedServerDespiteOldBackup(t *testing.T) {
	m := &dnsMachine{values: map[string][]string{"Wi-Fi": {tunnelDNS, "1.0.0.1"}, "USB Ethernet": {"Empty"}}}
	d := dnsSettings{filepath.Join(t.TempDir(), "dns-backup.json"), m.run}
	if err := os.WriteFile(d.path, []byte(`{"Wi-Fi":["9.9.9.9"]}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := d.restore(); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(m.values["Wi-Fi"], []string{"1.0.0.1"}) {
		t.Fatal("overwrote DNS added by user", m.values)
	}
}
