package platform

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestDNSReadinessWaitsForInstalledDictionary(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	reads := 0
	err := waitDNSRegistration(ctx, func(context.Context) ([]byte, error) {
		reads++
		if reads == 1 {
			return []byte("No such key"), nil
		}
		return []byte("ServerAddresses : " + tunnelDNS + "\nSupplementalMatchDomains :"), nil
	})
	if err != nil || reads != 2 {
		t.Fatal("asynchronous registration was not confirmed", reads, err)
	}
}

func TestDNSReadinessRejectsMissingOrDifferentDictionary(t *testing.T) {
	for _, value := range []string{"No such key", "ServerAddresses : " + tunnelDNS, "SupplementalMatchDomains : 1.1.1.1"} {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		err := waitDNSRegistration(ctx, func(context.Context) ([]byte, error) { return []byte(value), nil })
		if !errors.Is(err, context.Canceled) {
			t.Fatal("invalid DNS state reported ready", value, err)
		}
	}
	failure := errors.New("configd unavailable")
	if err := waitDNSRegistration(context.Background(), func(context.Context) ([]byte, error) { return nil, failure }); !errors.Is(err, failure) {
		t.Fatal("DNS read failure hidden", err)
	}
}
