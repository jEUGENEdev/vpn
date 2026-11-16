package owner

import (
	"encoding/binary"
	"errors"
	"net/netip"
)

// Windows IP Helper tables are parsed separately so ambiguity, truncated rows,
// IPv6, wildcard UDP binds and TCP SYN_SENT can be tested on every CI runner.
func tableOwner(data []byte, network string, ipv6 bool, source, dest netip.AddrPort) (uint32, error) {
	size, local, port, remote, remotePort, pid, state, iplen := 12, 0, 4, -1, -1, 8, -1, 4
	if network == "tcp" {
		size, local, port, remote, remotePort, pid, state = 24, 4, 8, 12, 16, 20, 0
	}
	if ipv6 {
		iplen = 16
		if network == "tcp" {
			size, local, port, remote, remotePort, pid, state = 56, 0, 20, 24, 44, 52, 48
		} else {
			size, local, port, pid = 28, 0, 20, 24
		}
	}
	if len(data) < 4 || uint64(binary.LittleEndian.Uint32(data)) > uint64((len(data)-4)/size) {
		return 0, errors.New("invalid owner table")
	}
	count := int(binary.LittleEndian.Uint32(data))
	var match uint32
	level := 0
	readPort := func(row []byte, offset int) uint16 { return binary.BigEndian.Uint16(row[offset : offset+2]) }
	for i := 0; i < count; i++ {
		row := data[4+i*size : 4+(i+1)*size]
		if state >= 0 {
			v := binary.LittleEndian.Uint32(row[state:])
			if v != 3 && v != 4 && v != 5 {
				continue
			}
		}
		if readPort(row, port) != source.Port() {
			continue
		}
		ip, _ := netip.AddrFromSlice(row[local : local+iplen])
		ip = ip.Unmap()
		candidate := 2
		if ip != source.Addr().Unmap() {
			if network != "udp" || !ip.IsUnspecified() {
				continue
			}
			candidate = 1
		}
		if remote >= 0 {
			other, _ := netip.AddrFromSlice(row[remote : remote+iplen])
			if other.Unmap() != dest.Addr().Unmap() || readPort(row, remotePort) != dest.Port() {
				continue
			}
		}
		owner := binary.LittleEndian.Uint32(row[pid:])
		if owner == 0 {
			continue
		}
		if candidate > level {
			match, level = owner, candidate
		} else if candidate == level && match != owner {
			return 0, errors.New("ambiguous connection owner")
		}
	}
	if match == 0 {
		return 0, errors.New("connection owner not found")
	}
	return match, nil
}
