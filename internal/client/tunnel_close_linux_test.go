//go:build linux && with_gvisor

package client

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/sagernet/gvisor/pkg/tcpip"
	"github.com/sagernet/gvisor/pkg/tcpip/link/fdbased"
	"github.com/sagernet/gvisor/pkg/tcpip/stack"
	tun "github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/logger"
	"golang.org/x/sys/unix"
)

type descriptorTestTunnel struct {
	*os.File
	endpoint stack.LinkEndpoint
}

func (t *descriptorTestTunnel) Name() (string, error)                { return "test", nil }
func (t *descriptorTestTunnel) Start() error                         { return nil }
func (t *descriptorTestTunnel) UpdateRouteOptions(tun.Options) error { return nil }
func (t *descriptorTestTunnel) NewEndpoint() (stack.LinkEndpoint, stack.NICOptions, error) {
	return t.endpoint, stack.NICOptions{}, nil
}
func (t *descriptorTestTunnel) WritePacket(packet *stack.PacketBuffer) (int, error) {
	var data []byte
	for _, part := range packet.AsSlices() {
		data = append(data, part...)
	}
	return t.File.Write(data)
}

// fdbased requires its descriptor to remain open until its reader has stopped.
// A socket pair exercises the real reader and gVisor shutdown without changing
// the host's network or requiring a privileged TUN.
func TestTunnelShutdownKeepsDescriptorAliveUntilReaderExits(t *testing.T) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fds[1])
	file := os.NewFile(uintptr(fds[0]), "test-tun")
	defer file.Close()
	readerExited := make(chan error, 1)
	endpoint, err := fdbased.New(&fdbased.Options{
		FDs: []int{fds[0]}, MTU: 1400, ProcessorsPerChannel: 1,
		ClosedFunc: func(tcpip.Error) {
			_, err := unix.FcntlInt(uintptr(fds[0]), unix.F_GETFD, 0)
			readerExited <- err
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	device := &descriptorTestTunnel{file, endpoint}
	c := testTrafficClient(t)
	options := c.stackOptions(context.Background(), device, tun.Options{})
	options.Logger = logger.NOP()
	packetStack, err := tun.NewStack("gvisor", options)
	if err != nil {
		t.Fatal(err)
	}
	if err = packetStack.Start(); err != nil {
		t.Fatal(err)
	}
	tunnel := &Tunnel{device: device, stack: packetStack, c: c}
	tunnel.Close()
	select {
	case err := <-readerExited:
		if err != nil {
			t.Fatalf("descriptor closed while packet reader was still active: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("packet reader did not stop")
	}
	if _, err := unix.FcntlInt(uintptr(fds[0]), unix.F_GETFD, 0); err != unix.EBADF {
		t.Fatalf("descriptor survived complete shutdown: %v", err)
	}
}
