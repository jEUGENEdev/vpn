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
	"net"
	"os"
	"path/filepath"
	"time"
)

type Desktop struct {
	Client  *client.Client
	Tunnel  *client.Tunnel
	owner   *owner.Desktop
	network tun.NetworkUpdateMonitor
	monitor tun.DefaultInterfaceMonitor
}

func Start(ctx context.Context, dir string) (*Desktop, error) {
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
	if !c.VPNEnabled() {
		// Also clean up a previous enabled process after a crash/update. Do this
		// before dropping privileges and never install a TUN for persisted off.
		if e = Recover(dir); e != nil {
			c.SetNetworkError(e)
		}
	} else {
		name := tun.CalculateInterfaceName("linevpn")
		monitor.RegisterMyInterface(name)
		// A persistent deny rule is installed BEFORE routes are changed. An error
		// intentionally leaves it in place; recovery is an explicit admin action.
		if e = Guard(""); e != nil {
			d.Close()
			return nil, e
		}
		t, e := c.StartTunnel(ctx, tun.Options{Name: name, AutoRoute: true, StrictRoute: true, InterfaceFinder: finder, InterfaceMonitor: monitor})
		if e != nil {
			d.Close()
			return nil, e
		}
		d.Tunnel = t
		if e = Guard(name); e != nil {
			d.Close()
			return nil, e
		}
		if e = ConfigureDNS(dir); e != nil {
			d.Close()
			return nil, e
		}
		c.SetGuard(true)
	}
	if e = DropPrivileges(dir); e != nil {
		d.Close()
		return nil, e
	}
	go c.Run(ctx)
	return d, nil
}
func (d *Desktop) Close() {
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
