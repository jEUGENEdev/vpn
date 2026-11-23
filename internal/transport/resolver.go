package transport

import (
	"context"
	"net"
	"syscall"
	"time"
)

// DirectResolver resolves intentionally direct traffic through the same socket
// protection/interface binding as its data connection. Protected destinations
// are resolved by the VPN server; this is not a fallback resolver for them.
func DirectResolver(control func(string, string, syscall.RawConn) error) *net.Resolver {
	return directResolver("1.1.1.1:53", control)
}

func directResolver(server string, control func(string, string, syscall.RawConn) error) *net.Resolver {
	return &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
		// Go retries truncated UDP replies over TCP. Preserve that choice and
		// apply protection to both sockets; never retry without Control.
		return (&net.Dialer{Timeout: 8 * time.Second, Control: control}).DialContext(ctx, network, server)
	}}
}
