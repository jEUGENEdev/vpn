package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"github.com/jEUGENEdev/vpn/internal/client"
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
	"runtime"
	"strings"
	"sync"
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
	recover := flag.Bool("recover-network", false, "explicitly restore DNS and remove LineVPN firewall rules")
	flag.Parse()
	if *recover {
		if e := platform.Recover(*dir); e != nil {
			log.Fatal(e)
		}
		return
	}
	run := func(ctx context.Context) error {
		// Cleanup also runs if profile/token preparation fails before Start.
		if err := platform.Recover(*dir); err != nil {
			log.Printf("network recovery: %v", err)
		}
		for {
			err := serve(ctx, *dir)
			// macOS dropped UID: launchd must start a fresh privileged instance.
			// Windows keeps its service identity and can restart in process.
			if !errors.Is(err, client.ErrNetworkRestart) || runtime.GOOS == "darwin" || ctx.Err() != nil {
				return err
			}
		}
	}
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
	ctx, cancel := context.WithCancel(ctx)
	d, e := platform.Start(ctx, dir)
	if e != nil {
		cancel()
		return e
	}
	defer d.Close()
	defer cancel()
	ln, e := net.Listen("tcp", "127.0.0.1:17891")
	if e != nil {
		return e
	}
	h := &http.Server{Handler: d.Client.Handler(token, ui.Handler("client")), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 20 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 30 * time.Second}
	restart := make(chan struct{})
	d.Client.SetNetworkController(&servicePower{restart: restart})
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		select {
		case <-ctx.Done():
		case <-restart:
		}
		shutdown, done := context.WithTimeout(context.Background(), 10*time.Second)
		defer done()
		// Flush the switching response before closing the old dataplane/DB.
		if err := h.Shutdown(shutdown); err != nil {
			h.Close()
		}
	}()
	fmt.Println("LineVPN service started")
	e = h.Serve(ln)
	if e == http.ErrServerClosed {
		<-stopped
		select {
		case <-restart:
			return client.ErrNetworkRestart
		default:
		}
		return nil
	}
	return e
}

type servicePower struct {
	restart chan struct{}
	once    sync.Once
}

func (*servicePower) Check(bool) error { return nil }
func (p *servicePower) Apply(bool) error {
	p.once.Do(func() { close(p.restart) })
	return client.ErrNetworkRestart
}
