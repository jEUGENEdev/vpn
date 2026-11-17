//go:build !android

package platform

import (
	"context"
	"errors"
	"github.com/jEUGENEdev/vpn/internal/client"
	"github.com/jEUGENEdev/vpn/internal/owner"
	"github.com/jEUGENEdev/vpn/internal/transport"
	tun "github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/control"
	"github.com/sagernet/sing/common/logger"
	"io"
	"net"
	"os"
	"path/filepath"
	"time"
)

type Desktop struct {
	Client  *client.Client
	Tunnel  *client.Tunnel
	owner   *owner.Desktop
	dns     io.Closer
	network tun.NetworkUpdateMonitor
	monitor tun.DefaultInterfaceMonitor
}

func Start(ctx context.Context, dir string) (*Desktop, error) {
	// A worker restart is not a request to turn protection off.
	networkError := prepareNetwork(dir, Guard, Recover)
	finder := control.NewDefaultInterfaceFinder()
	network, e := tun.NewNetworkUpdateMonitor(logger.NOP())
	if e != nil {
		return nil, e
	}
	if e = network.Start(); e != nil {
		return nil, e
	}
	monitor, e := tun.NewDefaultInterfaceMonitor(network, logger.NOP(), tun.DefaultInterfaceMonitorOptions{InterfaceFinder: finder})
	if e != nil {
		network.Close()
		return nil, e
	}
	if e = monitor.Start(); e != nil {
		network.Close()
		return nil, e
	}
	dialer := &transport.Dialer{Control: control.BindToInterfaceFunc(finder, func(network, address string) (string, int, error) {
		i := monitor.DefaultInterface()
		if i == nil {
			return "", 0, errors.New("нет сетевого подключения")
		}
		return i.Name, i.Index, nil
	})}
	dialer.Resolver = &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
		return (&net.Dialer{Timeout: 8 * time.Second, Control: dialer.Control}).DialContext(ctx, "udp", "1.1.1.1:53")
	}}
	transport.InstallDialer(dialer)
	c, e := client.New(dir, dialer)
	if e != nil {
		monitor.Close()
		network.Close()
		return nil, e
	}
	d := &Desktop{Client: c, network: network, monitor: monitor}
	if resolver, err := owner.NewDesktop(); err == nil {
		d.owner = resolver
		c.SetOwnerLookup(resolver.Lookup)
	}
	if networkError != nil {
		c.SetNetworkError(networkError)
	} else if c.VPNEnabled() {
		name := tun.CalculateInterfaceName("linevpn")
		monitor.RegisterMyInterface(name)
		// The persistent guard survives TUN/process loss. Only the agent can
		// egress directly; it applies address/application policy to every flow.
		t, err := c.StartTunnel(ctx, tun.Options{Name: name, AutoRoute: true, StrictRoute: false, InterfaceFinder: finder, InterfaceMonitor: monitor})
		if err != nil {
			c.SetNetworkError(err)
		} else if err = Guard(name); err != nil {
			t.Close()
			c.SetNetworkError(err)
		} else {
			dns, err := startTunnelDNS()
			if err != nil {
				t.Close()
				c.SetNetworkError(err)
			} else {
				d.Tunnel = t
				d.dns = dns
			}
		}
	}
	c.SetGuard(c.VPNEnabled() && networkError == nil)
	if e = DropPrivileges(dir); e != nil {
		d.Close()
		return nil, e
	}
	go c.Run(ctx)
	return d, nil
}
func (d *Desktop) Close() {
	if d.dns != nil {
		d.dns.Close()
	}
	if d.owner != nil {
		d.owner.Close()
	}
	if d.Client != nil {
		d.Client.Close()
	}
	if d.Tunnel != nil {
		d.Tunnel.Close()
	}
	if d.monitor != nil {
		d.monitor.Close()
	}
	if d.network != nil {
		d.network.Close()
	}
}
func DefaultDir() string {
	if p := os.Getenv("PROGRAMDATA"); p != "" {
		return filepath.Join(p, "LineVPN")
	}
	return "/var/lib/linevpn"
}
