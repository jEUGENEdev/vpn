package client

import (
	"context"
	"encoding/binary"
	"errors"
	tun "github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"io"
	"net"
	"net/netip"
	"os"
	"time"
)

type Tunnel struct {
	device tun.Tun
	stack  tun.Stack
	c      *Client
}

func (c *Client) StartTunnel(ctx context.Context, options tun.Options) (*Tunnel, error) {
	options.Logger = logger.NOP()
	options.MTU = 1400
	options.Inet4Address = []netip.Prefix{netip.MustParsePrefix("172.29.255.1/30")}
	options.Inet6Address = []netip.Prefix{netip.MustParsePrefix("fd04:6c69:6e65:ffff::1/126")}
	options.DNSAddress = []netip.Addr{netip.MustParseAddr("172.29.255.2")}
	options.EXP_MultiPendingPackets = true
	dev, e := tun.New(options)
	if e != nil {
		if options.FileDescriptor > 0 {
			os.NewFile(uintptr(options.FileDescriptor), "tun").Close()
		}
		return nil, e
	}
	st, e := tun.NewStack("gvisor", c.stackOptions(ctx, dev, options))
	if e != nil {
		dev.Close()
		return nil, e
	}
	if e = st.Start(); e != nil {
		st.Close()
		dev.Close()
		return nil, e
	}
	if e = dev.Start(); e != nil {
		st.Close()
		dev.Close()
		return nil, e
	}
	c.SetTunnel(true)
	return &Tunnel{dev, st, c}, nil
}

func (c *Client) stackOptions(ctx context.Context, dev tun.Tun, options tun.Options) tun.StackOptions {
	// One application socket can send media/STUN/QUIC to several destinations.
	// Each destination needs its own owner lookup, policy decision and upstream.
	// Endpoint-independent NAT would pass all of them to the first flow, whose
	// connected upstream intentionally accepts only that first destination.
	return tun.StackOptions{Context: ctx, Tun: dev, TunOptions: options, Handler: c, Logger: logger.NOP(), UDPTimeout: time.Minute,
		UDPMapping: tun.NATMappingAddressAndPortDependent, UDPFiltering: tun.NATFilteringAddressAndPortDependent}
}
func (t *Tunnel) Close() {
	t.c.SetTunnel(false)
	// Wake device readers before the network stack waits for them to stop.
	t.device.Close()
	t.stack.Close()
}
func (c *Client) JudgeFlow(network uint8, source, dest netip.AddrPort, first []byte) tun.FlowVerdict {
	if network != 6 && network != 17 {
		return tun.FlowVerdict{Action: tun.ActionReject}
	}
	if network == 17 && dest.Port() == 53 {
		return tun.FlowVerdict{Action: tun.ActionHijackDNS}
	}
	return tun.FlowVerdict{Action: tun.ActionAccept}
}
func (c *Client) NewDNSPacket(payload []byte, source, destination M.Socksaddr, writer N.PacketWriter) {
	if !c.reserveDNS() {
		if answer := dnsFailure(payload); answer != nil {
			writer.WritePacket(buf.As(answer), destination)
		}
		return
	}
	query := append([]byte(nil), payload...)
	go func() {
		defer func() { <-c.dnsSlots }()
		answer, err := c.answerDNS(context.Background(), query, destination.Addr, false)
		if err != nil {
			answer = dnsFailure(query)
		}
		if answer != nil {
			writer.WritePacket(buf.As(answer), destination)
		}
	}()
}
func (c *Client) NewConnectionEx(ctx context.Context, conn net.Conn, source, dest M.Socksaddr, onClose N.CloseHandlerFunc) {
	go func() {
		var result error
		defer func() {
			conn.Close()
			if onClose != nil {
				onClose(result)
			}
		}()
		if dest.Port == 53 {
			result = c.dnsTCP(ctx, conn, dest.Addr)
			return
		}
		target, e := c.target(dest.Addr)
		if e != nil {
			result = e
			return
		}
		up, e := c.dialApplication(ctx, "tcp", target, dest.Port, c.lookupApplication(ctx, "tcp", source.AddrPort(), dest.AddrPort()))
		if e != nil {
			result = e
			return
		}
		defer up.Close()
		done := make(chan struct{})
		go func() {
			io.Copy(up, conn)
			if v, ok := up.(interface{ CloseWrite() error }); ok {
				v.CloseWrite()
			} else {
				up.Close()
			}
			close(done)
		}()
		_, result = io.Copy(conn, up)
		conn.Close()
		up.Close()
		<-done
	}()
}
func (c *Client) dnsTCP(ctx context.Context, conn net.Conn, destination netip.Addr) error {
	for {
		conn.SetDeadline(time.Now().Add(30 * time.Second))
		var length [2]byte
		if _, e := io.ReadFull(conn, length[:]); e != nil {
			return e
		}
		n := binary.BigEndian.Uint16(length[:])
		if n < 12 || n > 4096 {
			return errors.New("invalid DNS frame")
		}
		q := make([]byte, n)
		if _, e := io.ReadFull(conn, q); e != nil {
			return e
		}
		answer := dnsFailure(q)
		if c.reserveDNS() {
			response, err := c.answerDNS(ctx, q, destination, true)
			<-c.dnsSlots
			if err == nil {
				answer = response
			}
		}
		if answer == nil {
			return errors.New("invalid DNS query")
		}
		binary.BigEndian.PutUint16(length[:], uint16(len(answer)))
		if _, e := conn.Write(append(length[:], answer...)); e != nil {
			return e
		}
	}
}
func (c *Client) NewPacketConnectionEx(ctx context.Context, conn N.PacketConn, source, dest M.Socksaddr, onClose N.CloseHandlerFunc) {
	go func() {
		var result error
		defer func() {
			conn.Close()
			if onClose != nil {
				onClose(result)
			}
		}()
		target, e := c.target(dest.Addr)
		if e != nil {
			result = e
			return
		}
		up, e := c.dialApplication(ctx, "udp", target, dest.Port, c.lookupApplication(ctx, "udp", source.AddrPort(), dest.AddrPort()))
		if e != nil {
			result = e
			return
		}
		defer up.Close()
		done := make(chan struct{})
		go func() {
			defer close(done)
			defer up.Close()
			for {
				b := buf.NewSize(65535)
				conn.SetReadDeadline(time.Now().Add(time.Minute))
				to, err := conn.ReadPacket(b)
				if err != nil {
					b.Release()
					return
				}
				if to != dest {
					b.Release()
					continue
				}
				_, err = up.Write(b.Bytes())
				b.Release()
				if err != nil {
					return
				}
			}
		}()
		reply := make([]byte, 65535)
		for {
			up.SetReadDeadline(time.Now().Add(time.Minute))
			n, err := up.Read(reply)
			if err != nil {
				result = err
				break
			}
			b := buf.NewSize(n)
			b.Write(reply[:n])
			if err = conn.WritePacket(b, dest); err != nil {
				result = err
				break
			}
		}
		conn.Close()
		up.Close()
		<-done
	}()
}
