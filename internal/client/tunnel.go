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
		return nil, e
	}
	st, e := tun.NewStack("gvisor", tun.StackOptions{Context: ctx, Tun: dev, TunOptions: options, Handler: c, Logger: logger.NOP(), UDPTimeout: time.Minute})
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
func (t *Tunnel) Close() { t.c.SetTunnel(false); t.stack.Close(); t.device.Close() }
func (c *Client) JudgeFlow(network uint8, source, dest netip.AddrPort, first []byte) tun.FlowVerdict {
	if network != 6 && network != 17 {
		return tun.FlowVerdict{Action: tun.ActionReject}
	}
	if dest.Port() == 853 {
		return tun.FlowVerdict{Action: tun.ActionReject}
	}
	if network == 17 && dest.Port() == 53 {
		return tun.FlowVerdict{Action: tun.ActionHijackDNS}
	}
	return tun.FlowVerdict{Action: tun.ActionAccept}
}
func (c *Client) NewDNSPacket(payload []byte, source, destination M.Socksaddr, writer N.PacketWriter) {
	answer, e := c.DNS.Answer(payload)
	if e == nil {
		writer.WritePacket(buf.As(answer), destination)
	}
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
			result = c.dnsTCP(conn)
			return
		}
		target, e := c.target(dest.Addr)
		if e != nil {
			result = e
			return
		}
		up, e := c.Dial(ctx, "tcp", target, dest.Port)
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
func (c *Client) dnsTCP(conn net.Conn) error {
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
		answer, e := c.DNS.Answer(q)
		if e != nil {
			return e
		}
		binary.BigEndian.PutUint16(length[:], uint16(len(answer)))
		if _, e = conn.Write(append(length[:], answer...)); e != nil {
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
		up, e := c.Dial(ctx, "udp", target, dest.Port)
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
