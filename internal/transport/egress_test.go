package transport

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"syscall"
	"testing"
	"time"
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

// Our alternative dialer returns a connected UDP socket, not Xray's full-cone
// PacketConnWrapper. A second destination cannot bypass the checked peer.
func TestConnectedUDPConnectionCannotChangeDestination(t *testing.T) {
	listener, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	// PublicOnly rejection is exercised above. Use a local first peer so this
	// socket-behavior fixture requires no Internet route and sends no packets out.
	first, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	d := &Dialer{}
	conn, err := d.DialContext(context.Background(), "udp", first.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	udp, ok := conn.(*net.UDPConn)
	if !ok {
		t.Fatalf("unexpected UDP socket %T", conn)
	}
	if _, err = udp.WriteToUDP([]byte("forbidden"), listener.LocalAddr().(*net.UDPAddr)); err == nil {
		t.Fatal("connected socket permitted another destination")
	}
	listener.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	if n, _, _ := listener.ReadFrom(make([]byte, 64)); n != 0 {
		t.Fatal("private destination received datagram")
	}
}

func TestPublicOnlyDeniesServerAddressBeforeSocketControl(t *testing.T) {
	for _, network := range []string{"tcp", "udp"} {
		controls := 0
		d := &Dialer{PublicOnly: true, Deny: []netip.Prefix{netip.MustParsePrefix("8.8.8.8/32")}, Control: func(string, string, syscall.RawConn) error { controls++; return errors.New("no network") }}
		if c, err := d.DialContext(context.Background(), network, "8.8.8.8:8443"); err == nil || c != nil || controls != 0 {
			t.Fatal("server self-egress allowed")
		}
	}
}
