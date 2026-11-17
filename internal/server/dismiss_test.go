package server

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jEUGENEdev/vpn/internal/model"
	"github.com/jEUGENEdev/vpn/internal/policy"
	"github.com/jEUGENEdev/vpn/internal/store"
)

func TestDismissWithFullDiscoveryQueue(t *testing.T) {
	for _, hasSubdomain := range []bool{false, true} {
		t.Run(fmt.Sprintf("subdomain=%t", hasSubdomain), func(t *testing.T) {
			s, call := deviceTestServer(t)
			device, err := s.enroll("a", "Laptop", "windows")
			if err != nil {
				t.Fatal(err)
			}
			phone, err := s.enroll("a", "Phone", "android")
			if err != nil {
				t.Fatal(err)
			}
			now := time.Now()
			if err := s.Store.Update(func(st *store.State) error {
				for i := 0; i < 1000; i++ {
					target := fmt.Sprintf("active-%d.example.org", i)
					if hasSubdomain && i == 0 {
						target = "mmg.whatsapp.net"
					}
					st.Requests["a:"+target] = model.Request{AccountID: "a", Target: target, Count: 3, FirstSeen: now, LastSeen: now, DirectFailed: true, FailedDevices: map[string]time.Time{device.DeviceID: now, phone.DeviceID: now}}
				}
				st.Requests["a:keep.example.com"] = model.Request{AccountID: "a", Target: "keep.example.com", Dismissed: true}
				st.Requests["b:mmg.whatsapp.net"] = model.Request{AccountID: "b", Target: "mmg.whatsapp.net", Count: 7}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			call("/api/dismiss", device.Token, map[string]string{"target": "WhatsApp.Net."}, 200)
			call("/api/dismiss", device.Token, map[string]string{"target": "whatsapp.net"}, 200)
			if err := s.Store.View(func(st store.State) error {
				if !st.Requests["a:whatsapp.net"].Dismissed || !st.Requests["a:keep.example.com"].Dismissed {
					t.Fatal("new or existing direct decision was lost")
				}
				if _, ok := st.Requests["a:mmg.whatsapp.net"]; ok {
					t.Fatal("covered subdomain still occupies the discovery queue")
				}
				want := 1003
				if hasSubdomain {
					want--
				}
				if len(st.Requests) != want || st.Requests["a:active-1.example.org"].Count != 3 || st.Requests["b:mmg.whatsapp.net"].Count != 7 {
					t.Fatal("dismissal evicted an unrelated request or crossed accounts")
				}
				if len(st.Accounts["a"].Rules) != 1 || st.Accounts["a"].Revision != 1 {
					t.Fatal("dismissal changed VPN permissions")
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			// The choice survives restart and suppresses future subdomains on both devices.
			path := s.Store.DB.Path()
			if err := s.Store.Close(); err != nil {
				t.Fatal(err)
			}
			s.Store, err = store.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { s.Store.Close() })
			call("/api/discover", phone.Token, map[string]any{"failed_targets": []string{"new.whatsapp.net"}}, 200)
			for _, token := range []string{device.Token, phone.Token} {
				sync := call("/api/sync", token, nil, 200)
				if len(sync["dismissed"].([]any)) != 2 {
					t.Fatal("direct decisions were not synchronized")
				}
				for _, item := range sync["requests"].([]any) {
					if policy.Matches("whatsapp.net", item.(map[string]any)["target"].(string)) {
						t.Fatal("dismissed domain returned in the queue")
					}
				}
			}
		})
	}
}

func TestDismissedDecisionsHaveSeparateCapacity(t *testing.T) {
	s, call := deviceTestServer(t)
	device, err := s.enroll("a", "Laptop", "windows")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Store.Update(func(st *store.State) error {
		for i := 0; i < 1000; i++ {
			target := fmt.Sprintf("keep-%d.example.com", i)
			st.Requests["a:"+target] = model.Request{AccountID: "a", Target: target, Dismissed: true}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	call("/api/discover", device.Token, map[string]any{"failed_targets": []string{"failed.example.org"}}, 200)
	sync := call("/api/sync", device.Token, nil, 200)
	requests := sync["requests"].([]any)
	if len(requests) != 1 || requests[0].(map[string]any)["target"] != "failed.example.org" {
		t.Fatal("saved decisions crowded out a new discovery")
	}
	// A separate, explicit preference limit still bounds storage and is not a 500.
	out := call("/api/dismiss", device.Token, map[string]string{"target": "failed.example.org"}, 409)
	if !strings.Contains(out["error"].(string), "сохранённых решений") {
		t.Fatal("preference limit reported as a discovery-queue failure")
	}
	call("/api/dismiss", device.Token, map[string]string{"target": "keep-0.example.com"}, 200)
	// Replacing many child choices with their parent works even at the limit.
	call("/api/dismiss", device.Token, map[string]string{"target": "example.com"}, 200)
	call("/api/dismiss", device.Token, map[string]string{"target": "new.example.com"}, 200)
	sync = call("/api/sync", device.Token, nil, 200)
	dismissed := sync["dismissed"].([]any)
	if len(dismissed) != 1 || dismissed[0] != "example.com" || len(sync["requests"].([]any)) != 1 {
		t.Fatal("parent compaction lost decisions or unrelated discoveries")
	}
	call("/api/dismiss", device.Token, map[string]string{"target": "failed.example.org"}, 200)
	if len(call("/api/sync", device.Token, nil, 200)["requests"].([]any)) != 0 {
		t.Fatal("existing discovery did not become a direct decision")
	}
}
