package platform

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// Registration is asynchronous. Only a read of the installed DNS dictionary
// can confirm readiness; a missing/incomplete key must not be reported as ready.
func waitDNSRegistration(ctx context.Context, read func(context.Context) ([]byte, error)) error {
	for {
		output, err := read(ctx)
		if err != nil {
			return fmt.Errorf("temporary DNS registration: %w", err)
		}
		if strings.Contains(string(output), tunnelDNS) && strings.Contains(string(output), "SupplementalMatchDomains") {
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("temporary DNS registration: %w", ctx.Err())
		case <-time.After(100 * time.Millisecond):
		}
	}
}
