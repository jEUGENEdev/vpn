//go:build !android || !with_gvisor

package client

import tun "github.com/sagernet/sing-tun"

func monitorTunnelReader(device tun.Tun, options tun.Options) (tun.Tun, func()) {
	return device, func() {}
}
