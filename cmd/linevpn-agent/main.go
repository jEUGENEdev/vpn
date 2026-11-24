package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"github.com/jEUGENEdev/vpn/internal/client"
	"github.com/jEUGENEdev/vpn/internal/desktopcontrol"
	"github.com/jEUGENEdev/vpn/internal/model"
	"github.com/jEUGENEdev/vpn/internal/owner"
	"github.com/jEUGENEdev/vpn/internal/platform"
	"github.com/jEUGENEdev/vpn/internal/secure"
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
	if len(os.Args) == 3 && os.Args[1] == "--identify-application" {
		info, err := owner.IdentifySelection(context.Background(), os.Args[2])
		if err != nil {
			log.Fatal(err)
		}
		if err := json.NewEncoder(os.Stdout).Encode(info); err != nil {
			log.Fatal(err)
		}
		return
	}
	if len(os.Args) == 3 && os.Args[1] == "--approve-control" {
		if err := approveControl(os.Args[2]); err != nil {
			log.Fatal(err)
		}
		return
	}
	if len(os.Args) == 2 && os.Args[1] == "--lookup-owner" {
		if e := owner.ServeHelper(); e != nil {
			log.Fatal(e)
		}
		return
	}
	prepare := flag.Bool("prepare-install", false, "prepare a fresh Windows installation after explicit removal")
	uninstall := flag.Bool("uninstall-state", false, "remove local Windows client state after the service stops")
	dir := flag.String("data", platform.DefaultDir(), "protected state directory")
	service := flag.Bool("service", false, "run as Windows service")
	check := flag.Bool("check-service", false, "wait for authenticated local service readiness without changing state")
	recover := flag.Bool("recover-network", false, "explicitly restore DNS and remove LineVPN firewall rules")
	flag.Parse()
	if *prepare || *uninstall {
		if err := cleanInstallation(*prepare); err != nil {
			reportInstallerError(err)
			log.Fatal(err)
		}
		return
	}
	if *check {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		if err := waitForService(ctx, *dir, "https://127.0.0.1:17891"); err != nil {
			log.Fatal(err)
		}
		return
	}
	if *recover {
		if e := platform.Recover(*dir); e != nil {
			log.Fatal(e)
		}
		return
	}
	run := func(ctx context.Context) error {
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
	// Reserve the public endpoint before publishing a fresh private session.
	ln, e := net.Listen("tcp", "127.0.0.1:17891")
	if e != nil {
		return e
	}
	defer ln.Close()
	control, e := desktopcontrol.Open(dir)
	if e != nil {
		return e
	}
	defer control.Listener.Close()
	// Publish only the public certificate, never the administrative credential.
	publicSession, e := json.Marshal(map[string]string{"certificate": control.Credentials.Certificate})
	if e != nil {
		return e
	}
	publicPath := filepath.Join(dir, "ui-session.json")
	if e = secure.Save(publicPath, publicSession); e != nil {
		return e
	}
	if e = tokenPermissions(dir, publicPath); e != nil {
		return e
	}
	ln = tls.NewListener(ln, control.TLS)
	ctx, cancel := context.WithCancel(ctx)
	d, e := platform.Start(ctx, dir)
	if e != nil {
		cancel()
		return e
	}
	defer d.Close()
	defer cancel()
	bridge := desktopcontrol.New(token, control.Credentials.Token, control.SettingsKey, d.Client.Handler(control.Credentials.Token, http.NotFoundHandler()), func(action string, data json.RawMessage) (string, error) {
		state := d.Client.State().(map[string]any)
		server, _ := state["server"].(string)
		return desktopcontrol.Description(action, data, server, func(id string) string {
			apps, _ := state["applications"].([]model.Application)
			for _, app := range apps {
				if app.ID == id {
					return app.Name + "\n" + app.Path
				}
			}
			return id
		})
	})
	h := &http.Server{Handler: bridge.Public(desktopHandler(d.Client, token, http.NotFoundHandler())), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 20 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 30 * time.Second}
	admin := &http.Server{Handler: bridge.Privileged(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 20 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 30 * time.Second}
	go func() {
		if err := admin.Serve(control.Listener); err != nil && err != http.ErrServerClosed {
			cancel()
		}
	}()
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
		// Flush the privileged commit response before a power change exits.
		if err := admin.Shutdown(shutdown); err != nil {
			admin.Close()
		}
	}()
	fmt.Println("Сеть: служба запущена")
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
