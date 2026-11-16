package policy

import "testing"

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
