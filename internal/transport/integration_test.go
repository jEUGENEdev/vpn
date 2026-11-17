package transport

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"github.com/jEUGENEdev/vpn/internal/model"
	"github.com/jEUGENEdev/vpn/internal/secure"
	"github.com/jEUGENEdev/vpn/internal/store"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// Exercises actual Xray VLESS + XHTTP + REALITY sockets, not a mocked proxy.
func TestREALITYXHTTPRoundTripAndDeny(t *testing.T) {
	target := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ordinary HTTPS site")) }))
	target.TLS = &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13}
	target.EnableHTTP2 = true
	target.StartTLS()
	defer target.Close()
	echo, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer echo.Close()
	var hits atomic.Int32
	go func() {
		for {
			c, e := echo.Accept()
			if e != nil {
				return
			}
			hits.Add(1)
			go func() { defer c.Close(); io.Copy(c, c) }()
		}
	}()
	free, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	port := free.Addr().(*net.TCPAddr).Port
	free.Close()
	key, _ := ecdh.X25519().GenerateKey(rand.Reader)
	pub := base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes())
	secret := base64.RawURLEncoding.EncodeToString(key.Bytes())
	uuid := secure.UUID()
	o := ServerOptions{Listen: "127.0.0.1", Port: port, PrivateKey: secret, PublicKey: pub, SNI: "example.com", Target: target.Listener.Addr().String(), ShortID: "12ab34cd", Path: "/test-xhttp"}
	st := store.Empty()
	st.Accounts["a"] = store.Account{Account: model.Account{ID: "a", Status: "active", Rules: []string{"127.0.0.1"}}}
	st.Devices["d"] = store.Device{Device: model.Device{ID: "d", AccountID: "a", Expires: time.Now().Add(time.Hour)}, Secret: uuid, AppSecret: secure.UUID()}
	InstallDialer(&Dialer{})
	var server, client, appClient Runtime
	defer server.Close()
	defer client.Close()
	defer appClient.Close()
	if e = server.Apply(loopbackTestConfig(ServerConfig(st, o, time.Now()))); e != nil {
		t.Fatal(e)
	}
	p := model.Profile{Server: "127.0.0.1", Port: port, UUID: uuid, SNI: o.SNI, PublicKey: pub, ShortID: o.ShortID, Path: o.Path}
	if e = client.Apply(ClientConfig(p)); e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	conn, e := client.Dial(ctx, "tcp", echo.Addr().String())
	if e != nil {
		t.Fatal(e)
	}
	defer conn.Close()
	go func() { <-ctx.Done(); conn.Close() }()
	if _, e = conn.Write([]byte("round-trip")); e != nil {
		t.Fatal(e)
	}
	reply := make([]byte, 10)
	if _, e = io.ReadFull(conn, reply); e != nil {
		t.Fatal(e)
	}
	if string(reply) != "round-trip" {
		t.Fatal(string(reply))
	}
	udpEcho, e := net.ListenPacket("udp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer udpEcho.Close()
	go func() {
		b := make([]byte, 65535)
		for {
			n, address, e := udpEcho.ReadFrom(b)
			if e != nil {
				return
			}
			udpEcho.WriteTo(b[:n], address)
		}
	}()
	udp, e := client.Dial(ctx, "udp", udpEcho.LocalAddr().String())
	if e != nil {
		t.Fatal(e)
	}
	defer udp.Close()
	udpTimer := time.AfterFunc(5*time.Second, func() { udp.Close() })
	defer udpTimer.Stop()
	for _, size := range []int{7, 1300, 3000} {
		payload := bytes.Repeat([]byte{byte(size)}, size)
		if _, e = udp.Write(payload); e != nil {
			t.Fatal(e)
		}
		response := make([]byte, 65535)
		n, e := udp.Read(response)
		if e != nil || !bytes.Equal(payload, response[:n]) {
			t.Fatalf("UDP datagram size %d: got %d bytes: %v", size, n, e)
		}
	}
	// Enrolling another device (and enabling its app credential) must not
	// interrupt the first device's already authenticated TCP/UDP streams.
	st.Devices["second"] = store.Device{Device: model.Device{ID: "second", AccountID: "a", Expires: time.Now().Add(time.Hour)}, Secret: secure.UUID(), AppSecret: secure.UUID()}
	if e = server.Apply(loopbackTestConfig(ServerConfig(st, o, time.Now()))); e != nil {
		t.Fatal(e)
	}
	if _, e = conn.Write([]byte("still-here")); e != nil {
		t.Fatal("second device interrupted first TCP stream:", e)
	}
	if _, e = io.ReadFull(conn, reply); e != nil || string(reply) != "still-here" {
		t.Fatal("first TCP stream lost after enrollment:", string(reply), e)
	}
	if _, e = udp.Write([]byte("media")); e != nil {
		t.Fatal(e)
	}
	if n, err := udp.Read(reply); err != nil || string(reply[:n]) != "media" {
		t.Fatal("first UDP stream lost after enrollment:", err)
	}
	var second Runtime
	defer second.Close()
	secondProfile := p
	secondProfile.UUID = st.Devices["second"].Secret
	if e = second.Apply(ClientConfig(secondProfile)); e != nil {
		t.Fatal(e)
	}
	other, e := second.Dial(ctx, "tcp", echo.Addr().String())
	if e != nil {
		t.Fatal(e)
	}
	defer other.Close()
	otherTimer := time.AfterFunc(5*time.Second, func() { other.Close() })
	defer otherTimer.Stop()
	if _, e = other.Write([]byte("two-online")); e != nil {
		t.Fatal(e)
	}
	if _, e = io.ReadFull(other, reply); e != nil || string(reply) != "two-online" {
		t.Fatal("second device cannot route alongside first:", e)
	}
	secondUDP, e := second.Dial(ctx, "udp", udpEcho.LocalAddr().String())
	if e != nil {
		t.Fatal(e)
	}
	defer secondUDP.Close()
	secondUDPTimer := time.AfterFunc(5*time.Second, func() { secondUDP.Close() })
	defer secondUDPTimer.Stop()
	for _, live := range []net.Conn{udp, secondUDP} {
		if _, e = live.Write([]byte("two-media")); e != nil {
			t.Fatal(e)
		}
		if n, err := live.Read(reply); err != nil || string(reply[:n]) != "two-media" {
			t.Fatal("simultaneous device UDP failed:", err)
		}
	}
	// Reapplying an unchanged policy must also preserve both sessions.
	if e = server.Apply(loopbackTestConfig(ServerConfig(st, o, time.Now()))); e != nil {
		t.Fatal(e)
	}
	for _, live := range []net.Conn{conn, other} {
		if _, e = live.Write([]byte("both-alive")); e != nil {
			t.Fatal(e)
		}
		if _, e = io.ReadFull(live, reply); e != nil || string(reply) != "both-alive" {
			t.Fatal("refresh interrupted a device:", e)
		}
	}
	// Widening existing IP and domain ACLs is additive too.
	for _, rule := range []string{"127.0.0.2", "example.com", "example.org"} {
		account := st.Accounts["a"]
		account.Rules = append(account.Rules, rule)
		st.Accounts["a"] = account
		if e = server.Apply(loopbackTestConfig(ServerConfig(st, o, time.Now()))); e != nil {
			t.Fatal(e)
		}
		if _, e = conn.Write([]byte("more-rules")); e != nil {
			t.Fatal(e)
		}
		if _, e = io.ReadFull(conn, reply); e != nil || string(reply) != "more-rules" {
			t.Fatal("adding permission interrupted a device:", e)
		}
	}
	conn.Close()
	udp.Close()
	a := st.Accounts["a"]
	a.Rules = nil
	st.Accounts["a"] = a
	if e = server.Apply(loopbackTestConfig(ServerConfig(st, o, time.Now()))); e != nil {
		t.Fatal(e)
	}
	client.Close()
	if e = client.Apply(ClientConfig(p)); e != nil {
		t.Fatal(e)
	}
	before := hits.Load()
	blocked, e := client.Dial(ctx, "tcp", echo.Addr().String())
	if e == nil {
		timer := time.AfterFunc(3*time.Second, func() { blocked.Close() })
		blocked.Write([]byte("must-not-pass"))
		n, _ := blocked.Read(make([]byte, 20))
		timer.Stop()
		blocked.Close()
		if n != 0 || hits.Load() != before {
			t.Fatal("server routed an unapproved destination")
		}
	}
	p.UUID = st.Devices["d"].AppSecret
	if e = appClient.Apply(ClientConfig(p)); e != nil {
		t.Fatal(e)
	}
	trusted, e := appClient.Dial(ctx, "tcp", echo.Addr().String())
	if e != nil {
		t.Fatal(e)
	}
	timer := time.AfterFunc(5*time.Second, func() { trusted.Close() })
	trusted.Write([]byte("trusted-app"))
	reply = make([]byte, len("trusted-app"))
	_, e = io.ReadFull(trusted, reply)
	timer.Stop()
	defer trusted.Close()
	if e != nil || string(reply) != "trusted-app" {
		t.Fatalf("trusted app tunnel failed for a destination outside address rules: %q %v", reply, e)
	}
	trustedUDP, e := appClient.Dial(ctx, "udp", udpEcho.LocalAddr().String())
	if e != nil {
		t.Fatal(e)
	}
	defer trustedUDP.Close()
	udpDeadline := time.AfterFunc(5*time.Second, func() { trustedUDP.Close() })
	trustedUDP.Write([]byte("before-delete"))
	udpReply := make([]byte, 64)
	nUDP, e := trustedUDP.Read(udpReply)
	if e != nil || string(udpReply[:nUDP]) != "before-delete" {
		t.Fatal("trusted UDP probe failed", e)
	}
	udpDeadline.Stop()
	// Keep address rules permitted: denial below must come from deletion.
	a.Rules = []string{"127.0.0.1"}
	st.Accounts["a"] = a
	delete(st.Devices, "d")
	if e = server.Apply(loopbackTestConfig(ServerConfig(st, o, time.Now()))); e != nil {
		t.Fatal(e)
	}
	closeTimer := time.AfterFunc(3*time.Second, func() { trusted.Close() })
	trusted.Write([]byte("after-deletion"))
	n, _ := trusted.Read(make([]byte, 32))
	closeTimer.Stop()
	if n != 0 {
		t.Fatal("existing trusted flow survived device deletion")
	}
	udpDeadline = time.AfterFunc(3*time.Second, func() { trustedUDP.Close() })
	trustedUDP.Write([]byte("after-delete"))
	nUDP, _ = trustedUDP.Read(udpReply)
	udpDeadline.Stop()
	if nUDP != 0 {
		t.Fatal("existing trusted UDP flow survived deletion")
	}
	appClient.Close()
	if e = appClient.Apply(ClientConfig(p)); e != nil {
		t.Fatal(e)
	}
	before = hits.Load()
	blocked, e = appClient.Dial(ctx, "tcp", echo.Addr().String())
	if e == nil {
		timer := time.AfterFunc(3*time.Second, func() { blocked.Close() })
		blocked.Write([]byte("revoked-app"))
		n, _ := blocked.Read(make([]byte, 20))
		timer.Stop()
		blocked.Close()
		if n != 0 || hits.Load() != before {
			t.Fatal("deleted device retained its app tunnel")
		}
	}
	p.UUID = uuid
	if e = client.Apply(ClientConfig(p)); e != nil {
		t.Fatal(e)
	}
	before = hits.Load()
	blocked, e = client.Dial(ctx, "tcp", echo.Addr().String())
	if e == nil {
		timer := time.AfterFunc(3*time.Second, func() { blocked.Close() })
		blocked.Write([]byte("deleted-address-key"))
		n, _ := blocked.Read(make([]byte, 32))
		timer.Stop()
		blocked.Close()
		if n != 0 || hits.Load() != before {
			t.Fatal("deleted device retained address tunnel")
		}
	}

}

// Xray 26.11 blocks private destinations in Freedom by default. Only this local
// transport test overrides that guard; production retains it and PublicOnly.
func loopbackTestConfig(c obj) obj {
	c["outbounds"].([]obj)[1]["settings"] = obj{"finalRules": []obj{{"action": "allow", "ip": []string{"127.0.0.1/32"}}}}
	return c
}
