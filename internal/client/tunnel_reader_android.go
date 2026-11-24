//go:build android && with_gvisor

package client

import (
	"log"
	"sync/atomic"

	"github.com/sagernet/gvisor/pkg/tcpip"
	"github.com/sagernet/gvisor/pkg/tcpip/link/fdbased"
	"github.com/sagernet/gvisor/pkg/tcpip/stack"
	tun "github.com/sagernet/sing-tun"
)

type monitoredAndroidTunnel struct {
	tun.GVisorTun
	fd     int
	mtu    uint32
	active atomic.Bool
}

func monitorTunnelReader(device tun.Tun, options tun.Options) (tun.Tun, func()) {
	base, ok := device.(tun.GVisorTun)
	if !ok || options.FileDescriptor <= 0 || options.GSO {
		return device, func() {}
	}
	deviceWithLog := &monitoredAndroidTunnel{GVisorTun: base, fd: options.FileDescriptor, mtu: options.MTU}
	deviceWithLog.active.Store(true)
	return deviceWithLog, func() { deviceWithLog.active.Store(false) }
}

func (device *monitoredAndroidTunnel) NewEndpoint() (stack.LinkEndpoint, stack.NICOptions, error) {
	endpoint, err := fdbased.New(&fdbased.Options{
		FDs: []int{device.fd}, MTU: device.mtu, ProcessorsPerChannel: 1, RXChecksumOffload: true,
		ClosedFunc: func(err tcpip.Error) {
			if device.active.Load() {
				log.Printf("VPN packet reader stopped unexpectedly: %v", err)
			}
		},
	})
	return endpoint, stack.NICOptions{}, err
}
