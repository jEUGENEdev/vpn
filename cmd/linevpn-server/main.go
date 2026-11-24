package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"github.com/jEUGENEdev/vpn/internal/secure"
	"github.com/jEUGENEdev/vpn/internal/server"
	"github.com/jEUGENEdev/vpn/internal/store"
	"github.com/jEUGENEdev/vpn/internal/transport"
	"github.com/jEUGENEdev/vpn/internal/ui"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

func main() {
	if err := run(); err != nil {
		log.Print(err)
		os.Exit(1)
	}
}

func run() error {
	path := flag.String("config", "/etc/linevpn/server.json", "configuration path")
	check := flag.Bool("check", false, "validate configuration without opening listeners")
	flag.Parse()
	raw, e := os.ReadFile(*path)
	if e != nil {
		return e
	}
	var cfg server.Config
	if e = json.Unmarshal(raw, &cfg); e != nil {
		return e
	}
	if e = cfg.Validate(); e != nil {
		return e
	}
	loader, e := secure.CertificateLoader(cfg.Cert, cfg.Key)
	if e != nil {
		return e
	}
	if *check {
		return nil
	}
	password, e := os.ReadFile(cfg.AdminPasswordFile)
	if e != nil {
		return e
	}
	st, e := store.Open(cfg.Database)
	if e != nil {
		return e
	}
	defer st.Close()
	publicIP := netip.MustParseAddr(cfg.PublicIP).Unmap()
	transport.InstallDialer(&transport.Dialer{PublicOnly: true, Deny: []netip.Prefix{netip.PrefixFrom(publicIP, publicIP.BitLen())}})
	cfg.Transport.BlockedIPs = append(cfg.Transport.BlockedIPs, cfg.PublicIP)
	var runtime transport.Runtime
	defer runtime.Close()
	apply := func(state store.State) error {
		return runtime.Apply(transport.ServerConfig(state, cfg.Transport, time.Now()))
	}
	s, e := server.New(st, cfg, strings.TrimRight(string(password), "\r\n"), apply)
	if e != nil {
		return e
	}
	s.ValidateApply = func(state store.State) error {
		if err := transport.ValidateConfig(transport.ServerConfig(state, cfg.Transport, time.Now())); err != nil {
			log.Printf("VPN configuration validation failed (%T)", err)
			return server.ErrInvalidConfiguration
		}
		return nil
	}
	if e = st.View(apply); e != nil {
		return e
	}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	defer cancel()

	newHTTPServer := func(address string, handler http.Handler) *http.Server {
		return &http.Server{Addr: address, Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 20 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16384, TLSConfig: &tls.Config{MinVersion: tls.VersionTLS13, GetCertificate: loader}}
	}
	h := newHTTPServer(cfg.Address, s.Handler(ui.Handler("admin")))
	admin := newHTTPServer(cfg.AdminListenAddress(), s.AdminHandler(ui.Handler("admin")))
	// Reserve both sockets before serving; failure must not leave half a deployment.
	publicListener, e := net.Listen("tcp", h.Addr)
	if e != nil {
		return e
	}
	defer publicListener.Close()
	adminListener, e := net.Listen("tcp", admin.Addr)
	if e != nil {
		return e
	}
	defer adminListener.Close()
	defer h.Close()
	defer admin.Close()
	serveErrors := make(chan error, 2)
	go func() {
		serveErrors <- admin.ServeTLS(adminListener, "", "")
	}()
	go func() {
		serveErrors <- h.ServeTLS(publicListener, "", "")
	}()
	go func() {
		tick := time.NewTicker(time.Minute)
		defer tick.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
				if e := s.Expire(time.Now()); e != nil {
					log.Printf("expired-device cleanup failed: %v", e)
				}
			}
		}
	}()
	log.Print("LineVPN server started")
	select {
	case e = <-serveErrors:
	case <-ctx.Done():
		e = nil
	}
	cancel()
	stop, stopCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer stopCancel()
	h.Shutdown(stop)
	admin.Shutdown(stop)
	if e == http.ErrServerClosed {
		return nil
	}
	return e
}
