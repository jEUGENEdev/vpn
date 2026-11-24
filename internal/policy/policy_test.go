package policy

import (
	"net/netip"
	"testing"
)

func TestPublicRejectsSpecialPurposeIPv6(t *testing.T) {
	for _, address := range []string{"2001:db8::1", "3fff::1", "3fff:fff:ffff::1", "100:0:0:1::1", "5f00::1", "2606:4700:4700::1111%eth0"} {
		t.Run(address, func(t *testing.T) {
			if Public(netip.MustParseAddr(address)) {
				t.Fatal("non-public IPv6 destination allowed")
			}
		})
	}
	for _, address := range []string{"1.1.1.1", "::ffff:1.1.1.1", "2606:4700:4700::1111", "2001:4860:4860::8888"} {
		if !Public(netip.MustParseAddr(address)) {
			t.Fatalf("ordinary public destination denied: %s", address)
		}
	}
}

func TestBoundaryAndInheritance(t *testing.T) {
	for _, c := range []struct {
		rule, host string
		want       bool
	}{{"example.com", "api.example.com", true}, {"example.com", "a.b.example.com", true}, {"example.com", "evil-example.com", false}, {"example.com", "example.com.evil.net", false}, {"1.2.3.4", "1.2.3.45", false}, {"1.2.3.4", "1.2.3.4", true}} {
		if got := Approved([]string{c.rule}, c.host); got != c.want {
			t.Fatal(c, got)
		}
	}
}
func TestInvalidTargets(t *testing.T) {
	for _, s := range []string{"com", "co.uk", "github.io", "*.example.com", "https://example.com", "example.com:443", "a..com", "127.1", "0127.0.0.1", "1.2.3.999", "fe80::1%eth0", "example.com/path", "_srv.example.com"} {
		if n, e := Normalize(s); e == nil {
			t.Fatalf("accepted %q as %q", s, n)
		}
	}
}
func TestNormalize(t *testing.T) {
	for in, want := range map[string]string{"EXAMPLE.COM.": "example.com", "пример.рф": "xn--e1afmkfd.xn--p1ai", "::ffff:1.2.3.4": "1.2.3.4"} {
		got, e := Normalize(in)
		if e != nil || got != want {
			t.Fatal(in, got, e)
		}
	}
}

func TestEquivalentIPSpellingsRetainProtection(t *testing.T) {
	for _, pair := range [][2]string{
		{"0000:0000:3101::ac40:9000", "0:0:3101::ac40:9000"},
		{"2A06:98C1:3101:0:0:0:AC40:9000", "2a06:98c1:3101::ac40:9000"},
		{"::ffff:172.64.144.0", "172.64.144.0"},
	} {
		for _, target := range pair {
			if !Approved([]string{pair[0]}, target) || !Matches(pair[1], target) {
				t.Fatalf("equivalent IP spelling lost protection: %v / %s", pair, target)
			}
		}
	}
}
func TestNoFallback(t *testing.T) {
	for _, ready := range []bool{true, false} {
		if Decide(nil, "example.com", ready) != Direct {
			t.Fatal("default")
		}
	}
	if Decide([]string{"example.com"}, "cdn.example.com", false) != Block {
		t.Fatal("leak")
	}
	if Decide([]string{"example.com"}, "cdn.example.com", true) != VPN {
		t.Fatal("route")
	}
}

func TestRejectDeprecatedSpecialNetworks(t *testing.T) {
	for _, address := range []string{"192.88.99.1", "fec0::1"} {
		if Public(netip.MustParseAddr(address)) {
			t.Fatal("special-purpose address accepted", address)
		}
	}
}
