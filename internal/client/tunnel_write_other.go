//go:build !linux || !with_gvisor

package client

import tun "github.com/sagernet/sing-tun"

func guardTunnelDevice(device tun.Tun) tun.Tun { return device }
