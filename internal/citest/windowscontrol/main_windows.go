//go:build windows && linevpn_ci

// This helper is compiled only for disposable CI machines, never into the VPN
// agent or installers. Preserve the Actions control channel while probes test
// the real, system-wide kill switch. Rules are non-persistent and removed by
// network recovery and the test's cleanup command.
package main

import (
	"crypto/sha256"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"github.com/tailscale/wf"
	"golang.org/x/sys/windows"
)

func guid(value string) windows.GUID {
	sum := sha256.Sum256([]byte(value))
	return *(*windows.GUID)(unsafe.Pointer(&sum[0]))
}

func main() {
	remove := flag.Bool("remove", false, "remove only CI controller rules")
	flag.Parse()
	if os.Getenv("GITHUB_ACTIONS") != "true" || len(flag.Args()) == 0 {
		log.Fatal("only for an isolated GitHub Actions runner with explicit controller paths")
	}
	paths := make([]string, 0, len(flag.Args()))
	for _, path := range flag.Args() {
		base := strings.ToLower(filepath.Base(path))
		if base != "runner.listener.exe" && base != "runner.worker.exe" {
			log.Fatal("only the Actions listener and worker may bypass the CI kill switch")
		}
		full, err := filepath.Abs(path)
		if err != nil {
			log.Fatal(err)
		}
		if _, err = os.Stat(full); err != nil {
			log.Fatal(err)
		}
		paths = append(paths, full)
	}
	session, err := wf.New(&wf.Options{Name: "LineVPN CI controller only", Dynamic: false})
	if err != nil {
		log.Fatal(err)
	}
	defer session.Close()
	provider := wf.ProviderID(guid("linevpn-provider"))
	sublayer := wf.SublayerID(guid("linevpn-sublayer"))
	layers := []wf.LayerID{wf.LayerALEAuthConnectV4, wf.LayerALEAuthConnectV6}
	ids := map[wf.RuleID]bool{}
	for _, path := range paths {
		for _, layer := range layers {
			ids[wf.RuleID(guid("linevpn-ci-control:"+strings.ToLower(path)+layer.String()))] = true
		}
	}
	if *remove {
		rules, err := session.Rules()
		if err != nil {
			log.Fatal(err)
		}
		for _, rule := range rules {
			if ids[rule.ID] {
				if err = session.DeleteRule(rule.ID); err != nil {
					log.Fatal(err)
				}
			}
		}
		return
	}
	providers, err := session.Providers()
	if err != nil {
		log.Fatal(err)
	}
	hasProvider := false
	for _, entry := range providers {
		hasProvider = hasProvider || entry.ID == provider
	}
	if !hasProvider {
		if err = session.AddProvider(&wf.Provider{ID: provider, Name: "LineVPN", Persistent: true}); err != nil {
			log.Fatal(err)
		}
	}
	sublayers, err := session.Sublayers(provider)
	if err != nil {
		log.Fatal(err)
	}
	hasSublayer := false
	for _, entry := range sublayers {
		hasSublayer = hasSublayer || entry.ID == sublayer
	}
	if !hasSublayer {
		if err = session.AddSublayer(&wf.Sublayer{ID: sublayer, Name: "LineVPN", Provider: provider, Persistent: true, Weight: 65535}); err != nil {
			log.Fatal(err)
		}
	}
	for _, path := range paths {
		app, err := wf.AppID(path)
		if err != nil {
			log.Fatal(err)
		}
		for _, layer := range layers {
			err = session.AddRule(&wf.Rule{
				ID:    wf.RuleID(guid("linevpn-ci-control:" + strings.ToLower(path) + layer.String())),
				Name:  "LineVPN CI controller (temporary)",
				Layer: layer, Sublayer: sublayer, Provider: provider,
				Persistent: false, Weight: 1000, Action: wf.ActionPermit, HardAction: true,
				Conditions: []*wf.Match{{Field: wf.FieldALEAppID, Op: wf.MatchTypeEqual, Value: app}},
			})
			if err != nil {
				log.Fatal(err)
			}
		}
	}
	fmt.Println("Temporary WFP permits installed for Actions controllers; all probe processes remain subject to the VPN rules")
}
