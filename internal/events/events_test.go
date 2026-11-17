package events

import (
	"strings"
	"testing"
	"time"

	"github.com/jEUGENEdev/vpn/internal/model"
)

func TestThrottle(t *testing.T) {
	c := New()
	n := time.Now()
	for i := 0; i < 100; i++ {
		c.Outage(n, "offline")
	}
	if len(c.List()) != 1 {
		t.Fatal("spam")
	}
	c.Recovered(n)
	c.Recovered(n)
	if len(c.List()) != 2 {
		t.Fatal("recovery")
	}
	c.FailedDirect(n, "a.example.com")
	c.FailedDirect(n, "b.example.com")
	c.FailedDirect(n, "c.example.com")
	if len(c.List()) != 3 {
		t.Fatal("suggestion")
	}
	c.FailedDirect(n, "other.com")
	c.FailedDirect(n, "other.com")
	if len(c.List()) != 3 {
		t.Fatal("global throttle")
	}
}

func TestEventCapturesTriggerAndKeepsHistoryIndependent(t *testing.T) {
	source := model.ApplicationInfo{ID: "browser-id", Name: "Browser", Path: "/apps/browser", Platform: "linux"}
	now := time.Now()
	tests := []struct {
		name string
		emit func(*Center, model.ApplicationInfo)
	}{
		{"suggestion", func(c *Center, app model.ApplicationInfo) { c.DirectUnavailable(now, "api.example.com", app) }},
		{"application", func(c *Center, app model.ApplicationInfo) { c.NewApplication(now, app, "api.example.com") }},
		{"outage", func(c *Center, app model.ApplicationInfo) { c.ConnectionOutage(now, "offline", "api.example.com", app) }},
		{"recovered", func(c *Center, app model.ApplicationInfo) {
			c.Outage(now, "offline")
			c.ConnectionRecovered(now, "api.example.com", app)
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			c := New()
			test.emit(c, source)
			items := c.List()
			event := items[len(items)-1]
			if event.Kind != test.name || event.Target != "api.example.com" || event.Source == nil || *event.Source != source {
				t.Fatalf("lost trigger context: %+v", event)
			}
			if !strings.Contains(event.Message, "Browser") || !strings.Contains(event.Message, "api.example.com") {
				t.Fatalf("native notification lacks context: %s", event.Message)
			}
			event.Source.Name = "changed by consumer"
			if items = c.List(); items[len(items)-1].Source.Name != source.Name {
				t.Fatal("consumer changed saved event source")
			}
		})
	}
}

func TestUnknownConnectionAndSystemEventAreDistinct(t *testing.T) {
	c := New()
	now := time.Now()
	c.DirectUnavailable(now, "2001:db8::1", model.ApplicationInfo{})
	c.Outage(now, "service offline")
	items := c.List()
	if items[0].Source != nil || items[0].Target != "2001:db8::1" || !strings.Contains(items[0].Message, "не определено") {
		t.Fatalf("unknown source not explicit: %+v", items[0])
	}
	if items[1].Source != nil || items[1].Target != "" || items[1].Message != "service offline" {
		t.Fatalf("system event acquired a request owner: %+v", items[1])
	}
}

func TestDifferentSourcesDoNotBypassNotificationThrottle(t *testing.T) {
	c := New()
	now := time.Now()
	for i := 0; i < 100; i++ {
		source := model.ApplicationInfo{ID: strings.Repeat("a", i+1), Name: "Browser", Path: "/apps/browser", Platform: "linux"}
		c.DirectUnavailable(now, "api.example.com", source)
		c.ConnectionOutage(now, "offline", "api.example.com", source)
	}
	items := c.List()
	if len(items) != 2 || items[0].Source.ID != "a" || items[1].Source.ID != "a" {
		t.Fatalf("throttle lost or original trigger overwritten: %+v", items)
	}
}

func TestFlappingDoesNotSpam(t *testing.T) {
	c := New()
	now := time.Now()
	for i := 0; i < 100; i++ {
		c.Outage(now.Add(time.Duration(i)*time.Second), "offline")
		c.Recovered(now.Add(time.Duration(i) * time.Second))
	}
	outages := 0
	for _, event := range c.List() {
		if event.Kind == "outage" {
			outages++
		}
	}
	if outages != 1 {
		t.Fatalf("flapping emitted %d outage notices", outages)
	}
}
