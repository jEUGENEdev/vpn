package transport

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/jEUGENEdev/vpn/internal/model"
	"github.com/jEUGENEdev/vpn/internal/secure"
	"github.com/jEUGENEdev/vpn/internal/store"
)

func TestConcurrentDevicesSurviveEnrollment(t *testing.T) {
	target := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ordinary HTTPS site")) }))
	target.TLS = &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13}
	target.EnableHTTP2 = true
	target.StartTLS()
	defer target.Close()
	tcp, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer tcp.Close()
	go func() {
		for {
			conn, err := tcp.Accept()
			if err != nil {
				return
			}
			go func() { defer conn.Close(); io.Copy(conn, conn) }()
		}
	}()
	udp, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	go func() {
		b := make([]byte, 65535)
		for {
			n, peer, err := udp.ReadFrom(b)
			if err != nil {
				return
			}
			udp.WriteTo(b[:n], peer)
		}
	}()
	free, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := free.Addr().(*net.TCPAddr).Port
	free.Close()
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	o := ServerOptions{Listen: "127.0.0.1", Port: port, PrivateKey: base64.RawURLEncoding.EncodeToString(key.Bytes()), PublicKey: base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes()), SNI: "example.com", Target: target.Listener.Addr().String(), ShortID: "12ab34cd", Path: "/concurrent"}
	s := store.Empty()
	s.Accounts["a"] = store.Account{Account: model.Account{ID: "a", Status: "active", Rules: []string{"127.0.0.1"}}}
	device := func(id string) store.Device {
		return store.Device{Device: model.Device{ID: id, AccountID: "a", Expires: time.Now().Add(time.Hour)}, Secret: secure.UUID(), AppSecret: secure.UUID()}
	}
	s.Devices["first"] = device("first")
	InstallDialer(&Dialer{})
	var server Runtime
	defer server.Close()
	apply := func() {
		t.Helper()
		cfg := loopbackTestConfig(ServerConfig(s, o, time.Now()))
		if err := server.Apply(cfg); err != nil {
			t.Fatal(err)
		}
	}
	apply()
	instance := server.instance
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	var flows []net.Conn
	open := func(id string) {
		t.Helper()
		for _, uuid := range []string{s.Devices[id].Secret, s.Devices[id].AppSecret} {
			client := new(Runtime)
			t.Cleanup(func() { client.Close() })
			p := model.Profile{Server: "127.0.0.1", Port: port, UUID: uuid, SNI: o.SNI, PublicKey: o.PublicKey, ShortID: o.ShortID, Path: o.Path}
			cfg := ClientConfig(p)
			if err := client.Apply(cfg); err != nil {
				t.Fatal(err)
			}
			for network, address := range map[string]string{"tcp": tcp.Addr().String(), "udp": udp.LocalAddr().String()} {
				conn, err := client.Dial(ctx, network, address)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { conn.Close() })
				flows = append(flows, conn)
			}
		}
	}
	probe := func(stage string) {
		t.Helper()
		var wg sync.WaitGroup
		for i, conn := range flows {
			wg.Add(1)
			go func() {
				defer wg.Done()
				timer := time.AfterFunc(10*time.Second, func() { conn.Close() })
				defer timer.Stop()
				if _, err := conn.Write([]byte("media")); err != nil {
					t.Errorf("%s flow %d write: %v", stage, i, err)
					return
				}
				b := make([]byte, 5)
				if _, err := io.ReadFull(conn, b); err != nil || string(b) != "media" {
					t.Errorf("%s flow %d round trip: %q %v", stage, i, b, err)
				}
			}()
		}
		wg.Wait()
	}
	open("first")
	probe("before enrollment")
	if t.Failed() {
		return
	}
	s.Devices["second"] = device("second")
	apply()
	if server.instance != instance {
		t.Fatal("enrolling another device restarted active transport")
	}
	open("second")
	probe("after enrollment") // Both devices, both credentials, TCP and UDP remain usable together.
	apply()
	if server.instance != instance {
		t.Fatal("unchanged state restarted transport")
	}
	probe("after no-op")
	delete(s.Devices, "second")
	apply()
	if server.instance == instance {
		t.Fatal("revocation did not cancel authenticated streams")
	}
}
