package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"github.com/jEUGENEdev/vpn/internal/server"
	"github.com/jEUGENEdev/vpn/internal/store"
	"github.com/jEUGENEdev/vpn/internal/transport"
	"github.com/jEUGENEdev/vpn/internal/ui"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

func main() {
	path := flag.String("config", "/etc/linevpn/server.json", "configuration path")
	check := flag.Bool("check", false, "validate configuration without opening listeners")
	flag.Parse()
	raw, e := os.ReadFile(*path)
	if e != nil {
		log.Fatal(e)
	}
	var cfg server.Config
	if e = json.Unmarshal(raw, &cfg); e != nil {
		log.Fatal(e)
	}
	if e = cfg.Validate(); e != nil {
		log.Fatal(e)
	}
	if *check {
		return
	}
	password, e := os.ReadFile(cfg.AdminPasswordFile)
	if e != nil {
		log.Fatal(e)
	}
	st, e := store.Open(cfg.Database)
	if e != nil {
		log.Fatal(e)
	}
	defer st.Close()
	transport.InstallDialer(&transport.Dialer{PublicOnly: true})
	var runtime transport.Runtime
	defer runtime.Close()
	apply := func(state store.State) error {
		return runtime.Apply(transport.ServerConfig(state, cfg.Transport, time.Now()))
	}
	s, e := server.New(st, cfg, strings.TrimSpace(string(password)), apply)
	if e != nil {
		log.Fatal(e)
	}
	if e = st.View(apply); e != nil {
		log.Fatal(e)
	}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	defer cancel()
	h := &http.Server{Addr: cfg.Address, Handler: s.Handler(ui.Handler("admin")), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 20 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16384, TLSConfig: &tls.Config{MinVersion: tls.VersionTLS13}}
	go func() {
		<-ctx.Done()
		stop, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		h.Shutdown(stop)
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
	if e = h.ListenAndServeTLS(cfg.Cert, cfg.Key); e != nil && e != http.ErrServerClosed {
		log.Fatal(e)
	}
}
