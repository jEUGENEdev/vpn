package main

import (
	"context"
	"github.com/jEUGENEdev/vpn/internal/platform"
	"golang.org/x/sys/windows/svc"
	"os/exec"
)

type handler struct{ run func(context.Context) error }

func (h handler) Execute(args []string, requests <-chan svc.ChangeRequest, changes chan<- svc.Status) (bool, uint32) {
	changes <- svc.Status{State: svc.StartPending}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- h.run(ctx) }()
	changes <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	for {
		select {
		case e := <-done:
			if e != nil {
				return false, 1
			}
			return false, 0
		case r := <-requests:
			switch r.Cmd {
			case svc.Stop, svc.Shutdown:
				changes <- svc.Status{State: svc.StopPending}
				cancel()
				<-done
				return false, 0
			case svc.Interrogate:
				changes <- r.CurrentStatus
			}
		}
	}
}
func runService(run func(context.Context) error) error { return svc.Run("LineVPN", handler{run}) }
func recoverNetwork() error                            { return platform.Recover() }
func tokenPermissions(dir, path string) error {
	if e := exec.Command("icacls", dir, "/inheritance:r", "/grant:r", "*S-1-5-18:(OI)(CI)F", "*S-1-5-32-544:(OI)(CI)F", "*S-1-5-32-545:(RX)").Run(); e != nil {
		return e
	}
	return exec.Command("icacls", path, "/inheritance:r", "/grant:r", "*S-1-5-18:F", "*S-1-5-32-544:F", "*S-1-5-32-545:R").Run()
}
