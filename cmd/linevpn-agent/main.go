package main

import (
	"context"
	"flag"
	"fmt"
	"github.com/jEUGENEdev/vpn/internal/owner"
	"github.com/jEUGENEdev/vpn/internal/platform"
	"github.com/jEUGENEdev/vpn/internal/secure"
	"github.com/jEUGENEdev/vpn/internal/ui"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

func main() {
	if len(os.Args) == 2 && os.Args[1] == "--lookup-owner" {
		if e := owner.ServeHelper(); e != nil {
			log.Fatal(e)
		}
		return
	}
	dir := flag.String("data", platform.DefaultDir(), "protected state directory")
	service := flag.Bool("service", false, "run as Windows service")
	recover := flag.Bool("recover-network", false, "explicitly remove Windows VPN firewall rules")
	flag.Parse()
	if *recover {
		if e := recoverNetwork(); e != nil {
			log.Fatal(e)
		}
		return
	}
	run := func(ctx context.Context) error { return serve(ctx, *dir) }
	if *service {
		if e := runService(run); e != nil {
			log.Fatal(e)
		}
		return
	}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	defer cancel()
	if e := run(ctx); e != nil {
		log.Fatal(e)
	}
}
func serve(ctx context.Context, dir string) error {
	if e := os.MkdirAll(dir, 0700); e != nil {
		return e
	}
	path := filepath.Join(dir, "ui-token")
	raw, e := os.ReadFile(path)
	var token string
	if e == nil {
		token = strings.TrimSpace(string(raw))
	} else if os.IsNotExist(e) {
		token = secure.Token()
		if e = secure.Save(path, []byte(token)); e != nil {
			return e
		}
	} else {
		return e
	}
	if e = tokenPermissions(dir, path); e != nil {
		return e
	}
	d, e := platform.Start(ctx, dir)
	if e != nil {
		return e
	}
	defer d.Close()
	ln, e := net.Listen("tcp", "127.0.0.1:17891")
	if e != nil {
		return e
	}
	h := &http.Server{Handler: d.Client.Handler(token, ui.Handler("client")), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 20 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 30 * time.Second}
	go func() { <-ctx.Done(); h.Close() }()
	fmt.Println("LineVPN service started")
	e = h.Serve(ln)
	if e == http.ErrServerClosed {
		return nil
	}
	return e
}
