package platform

import (
	"os"
	"os/exec"
	"testing"

	"github.com/tailscale/wf"
)

// Only a disposable elevated Windows host may install the legacy test objects.
// Match port 9 instead of all traffic, so the test cannot cut off CI control.
func TestLegacyRecoveryAndStandaloneScript(t *testing.T) {
	if os.Getenv("LINEVPN_NATIVE_RECOVERY_TEST") != "1" || os.Getenv("GITHUB_ACTIONS") != "true" {
		t.Skip("isolated Windows runner required")
	}
	s, err := wf.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	other := wf.ProviderID(guid("linevpn-ci-unrelated-provider"))
	if err := s.AddProvider(&wf.Provider{ID: other, Name: "Unrelated recovery test provider"}); err != nil {
		t.Fatal(err)
	}
	defer s.DeleteProvider(other)
	defer Recover(DefaultDir())
	for _, standalone := range []bool{false, true} {
		if err := s.AddProvider(&wf.Provider{ID: provider, Name: "LineVPN legacy fixture", Persistent: true}); err != nil {
			t.Fatal(err)
		}
		if err := s.AddSublayer(&wf.Sublayer{ID: sublayer, Provider: provider, Persistent: true, Weight: 65535}); err != nil {
			t.Fatal(err)
		}
		for _, layer := range []wf.LayerID{wf.LayerALEAuthConnectV4, wf.LayerALEAuthConnectV6} {
			if err := s.AddRule(&wf.Rule{ID: wf.RuleID(guid("deny" + layer.String())), Name: "LineVPN legacy test", Provider: provider, Sublayer: sublayer, Layer: layer, Persistent: true, Weight: 1, Action: wf.ActionBlock, Conditions: []*wf.Match{{Field: wf.FieldIPRemotePort, Op: wf.MatchTypeEqual, Value: uint16(9)}}}); err != nil {
				t.Fatal(err)
			}
		}
		for repeat := 0; repeat < 2; repeat++ {
			if standalone {
				out, err := exec.Command("powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "../../packaging/windows/recover-network.ps1").CombinedOutput()
				if err != nil {
					t.Fatalf("standalone recovery: %s: %v", out, err)
				}
			} else if err := Recover(DefaultDir()); err != nil {
				t.Fatal(err)
			}
		}
		providers, err := s.Providers()
		if err != nil {
			t.Fatal(err)
		}
		foundOther := false
		for _, p := range providers {
			if p.ID == provider {
				t.Fatal("legacy provider survived recovery")
			}
			foundOther = foundOther || p.ID == other
		}
		if !foundOther {
			t.Fatal("unrelated provider removed")
		}
	}
}
