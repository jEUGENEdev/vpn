package owner

import (
	"context"
	"github.com/jEUGENEdev/vpn/internal/model"
	"net/netip"
)

type Lookup func(context.Context, string, netip.AddrPort, netip.AddrPort) (model.ApplicationInfo, error)
