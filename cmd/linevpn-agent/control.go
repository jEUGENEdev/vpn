package main

import (
	"context"
	"github.com/jEUGENEdev/vpn/internal/desktopcontrol"
	"time"
)

func approveControl(id string) error {
	path, err := privilegedControlPath()
	if err != nil {
		return err
	}
	credentials, err := desktopcontrol.ReadCredentials(path)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	return desktopcontrol.Approve(ctx, credentials, id, confirmControl)
}
