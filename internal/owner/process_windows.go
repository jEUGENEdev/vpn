//go:build windows

package owner

import (
	"context"
	"errors"
	"golang.org/x/sys/windows"
	"io"
	"net/netip"
	"path/filepath"
	"unsafe"
)

func newProcessLookup() (processLookup, io.Closer, error) { return rawLookup, nil, nil }
func ServeHelper() error                                  { return errors.New("owner helper is only used on macOS") }
func rawLookup(ctx context.Context, network string, source, dest netip.AddrPort) (process, error) {
	fn := "GetExtendedTcpTable"
	class := uintptr(5)
	if network == "udp" {
		fn = "GetExtendedUdpTable"
		class = 1
	}
	family := uintptr(windows.AF_INET)
	if source.Addr().Unmap().Is6() {
		family = windows.AF_INET6
	}
	proc := windows.NewLazySystemDLL("iphlpapi.dll").NewProc(fn)
	data := make([]byte, 4096)
	for attempt := 0; attempt < 4; attempt++ {
		size := uint32(len(data))
		code, _, _ := proc.Call(uintptr(unsafe.Pointer(&data[0])), uintptr(unsafe.Pointer(&size)), 0, family, class, 0)
		if code == uintptr(windows.ERROR_INSUFFICIENT_BUFFER) {
			if size > 16<<20 {
				return process{}, errors.New("owner table too large")
			}
			data = make([]byte, size)
			continue
		}
		if code != 0 {
			return process{}, windows.Errno(code)
		}
		pid, err := tableOwner(data, network, family == windows.AF_INET6, source, dest)
		if err != nil {
			return process{}, err
		}
		h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
		if err != nil {
			return process{}, err
		}
		defer windows.CloseHandle(h)
		path := make([]uint16, 32768)
		length := uint32(len(path))
		if err = windows.QueryFullProcessImageName(h, 0, &path[0], &length); err != nil {
			return process{}, err
		}
		value := windows.UTF16ToString(path[:length])
		return process{int(pid), filepath.Base(value), value}, nil
	}
	return process{}, errors.New("owner table changed repeatedly")
}
