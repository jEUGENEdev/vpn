//go:build linux && with_gvisor

package client

import (
	"os"
	"sync"

	"github.com/sagernet/gvisor/pkg/tcpip"
	"github.com/sagernet/gvisor/pkg/tcpip/stack"
	tun "github.com/sagernet/sing-tun"
)

// Stopping the reader does not join every asynchronous DNS response or TCP
// teardown. Both writers below use a raw descriptor in sing-tun/gVisor, so an
// old packet could otherwise reach a newly opened file with the same number.
// Keep the gate shared by the forwarder and the network-stack endpoint.
type tunnelWriteGuard struct {
	tun.GVisorTun
	mu     sync.RWMutex
	closed bool
}

func guardTunnelDevice(device tun.Tun) tun.Tun {
	native, ok := device.(tun.GVisorTun)
	if !ok {
		return device
	}
	return &tunnelWriteGuard{GVisorTun: native}
}

func (t *tunnelWriteGuard) WritePacket(packet *stack.PacketBuffer) (int, error) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	if t.closed {
		return 0, os.ErrClosed
	}
	return t.GVisorTun.WritePacket(packet)
}

func (t *tunnelWriteGuard) NewEndpoint() (stack.LinkEndpoint, stack.NICOptions, error) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	if t.closed {
		return nil, stack.NICOptions{}, os.ErrClosed
	}
	endpoint, options, err := t.GVisorTun.NewEndpoint()
	if err != nil {
		return nil, options, err
	}
	return &guardedTunnelEndpoint{LinkEndpoint: endpoint, guard: t}, options, nil
}

func (t *tunnelWriteGuard) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return nil
	}
	t.closed = true
	return t.GVisorTun.Close()
}

type guardedTunnelEndpoint struct {
	stack.LinkEndpoint
	guard *tunnelWriteGuard
}

func (e *guardedTunnelEndpoint) WritePackets(packets stack.PacketBufferList) (int, tcpip.Error) {
	e.guard.mu.RLock()
	defer e.guard.mu.RUnlock()
	if e.guard.closed {
		return 0, &tcpip.ErrClosedForSend{}
	}
	return e.LinkEndpoint.WritePackets(packets)
}
