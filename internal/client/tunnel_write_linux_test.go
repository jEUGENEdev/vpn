//go:build linux && with_gvisor

package client

import (
	"testing"

	"github.com/sagernet/gvisor/pkg/buffer"
	"github.com/sagernet/gvisor/pkg/tcpip"
	"github.com/sagernet/gvisor/pkg/tcpip/stack"
	tun "github.com/sagernet/sing-tun"
	"golang.org/x/sys/unix"
)

type discardTunnelPackets struct{}

func (discardTunnelPackets) DeliverNetworkPacket(tcpip.NetworkProtocolNumber, *stack.PacketBuffer) {}
func (discardTunnelPackets) DeliverLinkPacket(tcpip.NetworkProtocolNumber, *stack.PacketBuffer)    {}

// Exercise both real raw-FD writers used by sing-tun. A delayed DNS response or
// TCP teardown must never write into an unrelated descriptor that reused the
// closed TUN number. No privileged interface or host route changes are needed.
func TestClosedTunnelCannotWriteToReusedDescriptor(t *testing.T) {
	for _, viaEndpoint := range []bool{false, true} {
		name := "forwarder"
		if viaEndpoint {
			name = "network_stack"
		}
		t.Run(name, func(t *testing.T) {
			fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, 0)
			if err != nil {
				t.Fatal(err)
			}
			defer unix.Close(fds[1])
			native, err := tun.New(tun.Options{FileDescriptor: fds[0], MTU: 1400, EXP_ExternalConfiguration: true})
			if err != nil {
				unix.Close(fds[0])
				t.Fatal(err)
			}
			device := guardTunnelDevice(native).(tun.GVisorTun)
			defer device.Close()
			endpoint, _, err := device.NewEndpoint()
			if err != nil {
				t.Fatal(err)
			}
			endpoint.Attach(discardTunnelPackets{})
			endpoint.Attach(nil)
			if err := device.Close(); err != nil {
				t.Fatal(err)
			}
			replacement, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, 0)
			if err != nil {
				t.Fatal(err)
			}
			defer unix.Close(replacement[0])
			defer unix.Close(replacement[1])
			if replacement[0] != fds[0] {
				if err := unix.Dup3(replacement[0], fds[0], unix.O_CLOEXEC); err != nil {
					t.Fatal(err)
				}
				defer unix.Close(fds[0])
			}
			packet := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(make([]byte, 40))})
			defer packet.DecRef()
			if viaEndpoint {
				var packets stack.PacketBufferList
				packets.PushBack(packet)
				if n, err := endpoint.WritePackets(packets); n != 0 || err == nil {
					t.Errorf("closed network stack wrote %d packets: %v", n, err)
				}
			} else if n, err := device.WritePacket(packet); n != 0 || err == nil {
				t.Errorf("closed forwarder wrote %d bytes: %v", n, err)
			}
			if n, _, err := unix.Recvfrom(replacement[1], make([]byte, 128), unix.MSG_DONTWAIT); n > 0 || err != unix.EAGAIN {
				t.Fatalf("late packet reached the reused descriptor: bytes=%d error=%v", n, err)
			}
		})
	}
}
