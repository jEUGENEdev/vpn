package owner

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSelectedBundleUsesItsDeclaredExecutable(t *testing.T) {
	bundle := filepath.Join(t.TempDir(), "Displayed Name.app")
	bin := filepath.Join(bundle, "Contents", "MacOS", "ActualBinary")
	if err := os.MkdirAll(filepath.Dir(bin), 0700); err != nil {
		t.Fatal(err)
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(exe)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bin, data, 0700); err != nil {
		t.Fatal(err)
	}
	plist := filepath.Join(bundle, "Contents", "Info.plist")
	writePlist := func(name string) {
		t.Helper()
		if err := os.WriteFile(plist, []byte(`<?xml version="1.0"?><plist version="1.0"><dict><key>CFBundleExecutable</key><string>`+name+`</string></dict></plist>`), 0600); err != nil {
			t.Fatal(err)
		}
	}
	writePlist("ActualBinary")
	app, err := IdentifySelection(t.Context(), bundle)
	if err != nil {
		t.Fatal(err)
	}
	binary, err := IdentifySelection(t.Context(), bin)
	if err != nil || binary.ID != app.ID || app.Name != "Displayed Name" {
		t.Fatal("bundle selected the wrong executable", err)
	}
	writePlist("../Escape")
	if _, err = IdentifySelection(t.Context(), bundle); err == nil {
		t.Fatal("invalid bundle executable accepted")
	}
}
