package events

import (
	"testing"
	"time"
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
