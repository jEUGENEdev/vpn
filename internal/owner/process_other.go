//go:build !android && !darwin && !windows

package owner

import (
	"context"
	"errors"
	xnet "github.com/xtls/xray-core/common/net"
	"io"
	"net/netip"
)

func rawLookup(ctx context.Context, network string, source, dest netip.AddrPort) (process, error) {
	pid, name, path, err := xnet.FindProcess(network, source.Addr().String(), source.Port(), dest.Addr().String(), dest.Port())
	return process{pid, name, path}, err
}
func newProcessLookup() (processLookup, io.Closer, error) { return rawLookup, nil, nil }
func ServeHelper() error                                  { return errors.New("owner helper is only used on macOS") }
