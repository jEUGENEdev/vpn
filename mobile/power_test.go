package mobile

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type idleService struct {
	opens    int
	lockdown bool
}

func (*idleService) Protect(int64) bool                                             { return true }
func (*idleService) DeviceName() string                                             { return "Test phone" }
func (*idleService) ResolveApplication(string, string, int64, string, int64) string { return "{}" }
func (p *idleService) OpenTunnel() (int64, error) {
	p.opens++
	return 0, errors.New("VPN permission revoked")
}
func (p *idleService) CheckDisable() error {
	if p.lockdown {
		return errors.New("Android lockdown")
	}
	return nil
}

func TestAndroidOffStartupKeepsUIWithoutOpeningVPN(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "core"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "core/profile.json"), []byte(`{"vpn_disabled":true}`), 0600); err != nil {
		t.Fatal(err)
	}
	p := &idleService{}
	url, err := Start(dir, p)
	if err != nil {
		t.Fatal(err)
	}
	defer Stop()
	if p.opens != 0 || url == "" || !strings.Contains(Snapshot(), `"status":"disabled"`) {
		t.Fatal(Snapshot(), p.opens)
	}
	if err = current.c.SetVPNEnabled(true); err == nil {
		t.Fatal("native enable failure hidden")
	}
	if !strings.Contains(Snapshot(), `"status":"network_error"`) || p.opens != 1 {
		t.Fatal(Snapshot(), p.opens)
	}
	// The local UI still exists and explicit off can recover from a failed enable.
	if err = current.c.SetVPNEnabled(false); err != nil {
		t.Fatal(err)
	}
	if URL() != url || !strings.Contains(Snapshot(), `"status":"disabled"`) {
		t.Fatal(Snapshot())
	}
	Stop()
	p.lockdown = true
	if _, err = Start(dir, p); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(Snapshot(), `"status":"system_blocked"`) || p.opens != 1 {
		t.Fatal("lockdown falsely reported direct access", Snapshot())
	}
}
