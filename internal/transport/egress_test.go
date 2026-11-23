package transport

import (
	"context"
	"errors"
	"net"
	"syscall"
	"testing"
)

func TestPublicOnlyRejectsSpecialAddressesBeforeSocketControl(t *testing.T) {
	for _, network := range []string{"tcp", "udp"} {
		for _, address := range []string{
			"127.0.0.1", "::ffff:127.0.0.1", "169.254.169.254", "fc00::1", "172.29.255.2", "192.168.0.1",
			"2001:db8::1", "3fff::1", "100:0:0:1::1", "5f00::1", "2606:4700:4700::1111%eth0",
		} {
			t.Run(network+"/"+address, func(t *testing.T) {
				calls := 0
				dialer := &Dialer{PublicOnly: true, Control: func(string, string, syscall.RawConn) error {
					calls++
					return errors.New("test forbids all network traffic")
				}}
				for _, port := range []string{"443", "853"} {
					conn, err := dialer.DialContext(context.Background(), network, net.JoinHostPort(address, port))
					if conn != nil {
						conn.Close()
						t.Fatal("non-public egress opened a connection")
					}
					if err == nil || calls != 0 {
						t.Fatalf("non-public destination reached socket creation: error=%v controls=%d", err, calls)
					}
				}
			})
		}
	}
}
