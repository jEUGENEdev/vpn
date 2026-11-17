//go:build !darwin

package platform

import "io"

// Windows DNS belongs to the Wintun interface. Android uses VpnService.
func startTunnelDNS() (io.Closer, error) { return nil, nil }
