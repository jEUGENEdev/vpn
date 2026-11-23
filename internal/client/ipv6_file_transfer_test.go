package client

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	quic "github.com/apernet/quic-go"
	"github.com/apernet/quic-go/http3"
	"github.com/jEUGENEdev/vpn/internal/model"
	"github.com/jEUGENEdev/vpn/internal/secure"
	"github.com/jEUGENEdev/vpn/internal/store"
	"github.com/jEUGENEdev/vpn/internal/transport"
	tun "github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// Exercise uploads, complete downloads and parallel byte ranges through the
// production TCP/UDP handlers and real VLESS/XHTTP/REALITY to an IPv6 HTTPS origin.
// The only synthetic parts are the OS owner lookup and the application's TUN
// connection. No public service or user file is contacted or copied.
func TestSelectiveIPv6FileTransfer(t *testing.T) {
	file := make([]byte, 8<<20)
	if _, err := rand.Read(file); err != nil {
		t.Fatal(err)
	}
	wantHash := sha256.Sum256(file)
	for _, decision := range []string{"addresses", "trusted"} {
		for _, version := range []int{1, 2, 3} {
			t.Run(fmt.Sprintf("%s/http%d", decision, version), func(t *testing.T) {
				origin := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.Method == http.MethodPost {
						hash := sha256.New()
						n, err := io.Copy(hash, io.LimitReader(r.Body, int64(len(file)+1)))
						if err != nil || n != int64(len(file)) || !bytes.Equal(hash.Sum(nil), wantHash[:]) {
							http.Error(w, "upload was truncated or changed", http.StatusBadRequest)
							return
						}
						w.WriteHeader(http.StatusNoContent)
						return
					}
					http.ServeContent(w, r, "fixture.bin", time.Unix(1, 0), bytes.NewReader(file))
				}))
				origin.Listener.Close()
				listener, err := net.Listen("tcp6", "[::1]:0")
				if err != nil {
					t.Fatal(err)
				}
				origin.Listener = listener
				origin.EnableHTTP2 = true
				origin.TLS = &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13}
				origin.StartTLS()
				t.Cleanup(origin.Close)
				destination := listener.Addr().(*net.TCPAddr).AddrPort()
				if version == 3 {
					udp, err := net.ListenPacket("udp6", destination.String())
					if err != nil {
						t.Fatal(err)
					}
					server := &http3.Server{TLSConfig: origin.TLS.Clone(), Handler: origin.Config.Handler}
					served := make(chan error, 1)
					go func() { served <- server.Serve(udp) }()
					t.Cleanup(func() {
						server.Close()
						udp.Close()
						if err := <-served; err != nil && !errors.Is(err, http.ErrServerClosed) && !errors.Is(err, net.ErrClosed) {
							t.Error(err)
						}
					})
				}
				transport.InstallDialer(&transport.Dialer{Control: func(_, address string, _ syscall.RawConn) error {
					endpoint, err := netip.ParseAddrPort(address)
					if err != nil || !endpoint.Addr().IsLoopback() {
						return errors.New("file transfer test prohibits external sockets")
					}
					return nil
				}})
				t.Cleanup(func() { transport.InstallDialer(&transport.Dialer{}) })
				free, err := net.Listen("tcp4", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				port := free.Addr().(*net.TCPAddr).Port
				free.Close()
				key, err := ecdh.X25519().GenerateKey(rand.Reader)
				if err != nil {
					t.Fatal(err)
				}
				options := transport.ServerOptions{Listen: "127.0.0.1", Port: port,
					PrivateKey: base64.RawURLEncoding.EncodeToString(key.Bytes()), PublicKey: base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes()),
					SNI: "example.com", Target: listener.Addr().String(), ShortID: "12ab34cd", Path: "/ipv6-file-test"}
				rules := []string{}
				if decision == "addresses" {
					rules = []string{destination.Addr().String()}
				}
				st := store.Empty()
				st.Accounts["a"] = store.Account{Account: model.Account{ID: "a", Status: "active", Rules: rules}}
				device := store.Device{Device: model.Device{ID: "d", AccountID: "a", Expires: time.Now().Add(time.Hour)}, Secret: secure.UUID(), AppSecret: secure.UUID()}
				st.Devices["d"] = device
				cfg := transport.ServerConfig(st, options, time.Now())
				// Test-local origin only; production private-address denial is intact.
				cfg["outbounds"].([]map[string]any)[1]["settings"] = map[string]any{"finalRules": []map[string]any{{"action": "allow", "ip": []string{"::1/128"}}}}
				var server transport.Runtime
				if err := server.Apply(cfg); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { server.Close() })
				var directAttempts atomic.Int32
				c, err := New(t.TempDir(), &transport.Dialer{Control: func(string, string, syscall.RawConn) error {
					directAttempts.Add(1)
					return errors.New("file transfer attempted direct egress")
				}})
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(c.Close)
				c.config.TrafficMode = TrafficSelective
				app := testApp("a")
				c.apps[app.ID] = model.Application{ApplicationInfo: app, Decision: decision}
				source := netip.MustParseAddrPort("[fd04:6c69:6e65:ffff::1]:12345")
				c.SetOwnerLookup(func(_ context.Context, network string, src, dst netip.AddrPort) (model.ApplicationInfo, error) {
					wantNetwork := "tcp"
					if version == 3 {
						wantNetwork = "udp"
					}
					if network != wantNetwork || src != source || dst != destination {
						t.Error("file transfer lost the original IPv6 tuple")
					}
					return app, nil
				})
				p := model.Profile{AccountID: "a", DeviceID: "d", Status: "active", Rules: rules, UUID: device.Secret,
					Server: "127.0.0.1", Port: port, SNI: options.SNI, PublicKey: options.PublicKey, ShortID: options.ShortID, Path: options.Path}
				if decision == "trusted" {
					p.AppUUID = device.AppSecret
				}
				if err := c.apply(p); err != nil {
					t.Fatal(err)
				}
				httpsTransport := &http.Transport{
					TLSClientConfig: origin.Client().Transport.(*http.Transport).TLSClientConfig.Clone(), ForceAttemptHTTP2: version == 2,
					DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
						if network != "tcp" || address != destination.String() {
							return nil, fmt.Errorf("unexpected file endpoint: %s %s", network, address)
						}
						left, right := net.Pipe()
						c.NewConnectionEx(ctx, left, M.SocksaddrFrom(source.Addr(), source.Port()), M.SocksaddrFrom(destination.Addr(), destination.Port()), nil)
						return right, nil
					},
				}
				t.Cleanup(httpsTransport.CloseIdleConnections)
				https := &http.Client{Transport: httpsTransport, Timeout: 20 * time.Second}
				if version == 3 {
					https.Transport = fileTransferHTTP3(t, c, source, destination, httpsTransport.TLSClientConfig)
				}
				response, err := https.Post(origin.URL+"/file", "application/octet-stream", bytes.NewReader(file))
				if err != nil {
					t.Fatal("upload", err)
				}
				response.Body.Close()
				if response.StatusCode != http.StatusNoContent || response.ProtoMajor != version {
					t.Fatalf("upload: status=%d protocol=%s", response.StatusCode, response.Proto)
				}
				checkDownload := func(start, end int, partial bool) error {
					request, _ := http.NewRequest(http.MethodGet, origin.URL+"/file", nil)
					status := http.StatusOK
					if partial {
						request.Header.Set("Range", fmt.Sprintf("bytes=%d-%d", start, end-1))
						status = http.StatusPartialContent
					}
					response, err := https.Do(request)
					if err != nil {
						return err
					}
					defer response.Body.Close()
					data, err := io.ReadAll(response.Body)
					if err != nil || response.StatusCode != status || !bytes.Equal(data, file[start:end]) {
						return fmt.Errorf("download %d:%d: status=%d bytes=%d error=%v", start, end, response.StatusCode, len(data), err)
					}
					return nil
				}
				if err := checkDownload(0, len(file), false); err != nil {
					t.Fatal(err)
				}
				results := make(chan error, 2)
				go func() { results <- checkDownload(0, len(file)/2, true) }()
				go func() { results <- checkDownload(len(file)/2, len(file), true) }()
				for range 2 {
					if err := <-results; err != nil {
						t.Error(err)
					}
				}
				if directAttempts.Load() != 0 {
					t.Fatal("file transfer bypassed VPN")
				}
				c.mu.RLock()
				issues := c.vpnIssuesLocked()
				c.mu.RUnlock()
				if len(issues) != 0 {
					t.Fatal("successful file transfer reported an outage", issues)
				}
			})
		}
	}
}

type fileTransferUDPReply struct {
	net.PacketConn
	peer        net.Addr
	destination M.Socksaddr
}

func (w fileTransferUDPReply) WritePacket(b *buf.Buffer, destination M.Socksaddr) error {
	defer b.Release()
	if destination != w.destination {
		return errors.New("file transfer reply changed its IPv6 peer")
	}
	_, err := w.WriteTo(b.Bytes(), w.peer)
	return err
}

// Local UDP sockets stand in for the application's packet link. Every QUIC
// datagram crosses the production NAT and UDP handler before entering Xray.
func fileTransferHTTP3(t *testing.T, c *Client, source, destination netip.AddrPort, tlsConfig *tls.Config) http.RoundTripper {
	t.Helper()
	application, err := net.ListenPacket("udp6", "[::1]:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { application.Close() })
	link, err := net.ListenPacket("udp6", "[::1]:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { link.Close() })
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	dest := M.SocksaddrFrom(destination.Addr(), destination.Port())
	src := M.SocksaddrFrom(source.Addr(), source.Port())
	options := c.stackOptions(ctx, nil, tun.Options{})
	replies := fileTransferUDPReply{link, application.LocalAddr(), dest}
	nat := tun.NewUDPNat(tun.UDPNatOptions{Handler: c, Timeout: options.UDPTimeout, Mapping: options.UDPMapping, Filtering: options.UDPFiltering,
		Prepare: func(_, _ M.Socksaddr, _ any) (bool, context.Context, N.PacketWriter, N.CloseHandlerFunc) {
			return true, ctx, replies, nil
		},
	})
	if err := nat.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { nat.Close() })
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		packet := make([]byte, 65535)
		for {
			n, peer, err := link.ReadFrom(packet)
			if err != nil {
				return
			}
			if peer.String() != application.LocalAddr().String() {
				t.Error("unexpected file transfer packet source")
				return
			}
			nat.NewPacket([][]byte{packet[:n]}, src, dest, nil)
		}
	}()
	t.Cleanup(func() { link.Close(); <-finished })
	quicTransport := &quic.Transport{Conn: application}
	t.Cleanup(func() { quicTransport.Close() })
	h3 := &http3.Transport{
		TLSClientConfig: tlsConfig.Clone(),
		Dial: func(ctx context.Context, address string, config *tls.Config, options *quic.Config) (*quic.Conn, error) {
			if address != destination.String() {
				return nil, fmt.Errorf("unexpected QUIC file endpoint: %s", address)
			}
			return quicTransport.DialEarly(ctx, link.LocalAddr(), config, options)
		},
	}
	t.Cleanup(func() { h3.Close() })
	return h3
}
