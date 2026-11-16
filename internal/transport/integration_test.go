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
	"strconv"
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
	st.Devices["d"] = store.Device{Device: model.Device{ID: "d", AccountID: "a", Expires: time.Now().Add(time.Hour)}, Secret: uuid}
	InstallDialer(&Dialer{})
	var server, client Runtime
	defer server.Close()
	defer client.Close()
	if e = server.Apply(loopbackTestConfig(ServerConfig(st, o, time.Now()))); e != nil {
		t.Fatal(e)
	}
	p := model.Profile{Server: "127.0.0.1", Port: port, UUID: uuid, SNI: o.SNI, PublicKey: pub, ShortID: o.ShortID, Path: o.Path}
	if e = client.Apply(ClientConfig(p)); e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
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
	conn.Close()
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
	blocked, e := client.Dial(ctx, "tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(echo.Addr().(*net.TCPAddr).Port)))
	if e != nil {
		return
	}
	defer blocked.Close()
	timer := time.AfterFunc(3*time.Second, func() { blocked.Close() })
	defer timer.Stop()
	blocked.Write([]byte("must-not-pass"))
	n, _ := blocked.Read(make([]byte, 20))
	if n != 0 || hits.Load() != before {
		t.Fatal("server routed an unapproved destination")
	}
}

// Xray 26.11 blocks private destinations in Freedom by default. Only this local
// transport test overrides that guard; production retains it and PublicOnly.
func loopbackTestConfig(c obj) obj {
	c["outbounds"].([]obj)[1]["settings"] = obj{"finalRules": []obj{{"action": "allow", "ip": []string{"127.0.0.1/32"}}}}
	return c
}
