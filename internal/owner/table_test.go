package owner

import (
	"encoding/binary"
	"net/netip"
	"testing"
)

func ownerRow(network string, ipv6 bool, pid uint32, src, dst netip.AddrPort) []byte {
	size, l, p, r, rp, owner, state, n := 12, 0, 4, -1, -1, 8, -1, 4
	if network == "tcp" {
		size, l, p, r, rp, owner, state = 24, 4, 8, 12, 16, 20, 0
	}
	if ipv6 {
		n = 16
		if network == "tcp" {
			size, l, p, r, rp, owner, state = 56, 0, 20, 24, 44, 52, 48
		} else {
			size, l, p, owner = 28, 0, 20, 24
		}
	}
	row := make([]byte, size)
	copy(row[l:l+n], src.Addr().AsSlice())
	binary.BigEndian.PutUint16(row[p:], src.Port())
	binary.LittleEndian.PutUint32(row[owner:], pid)
	if r >= 0 {
		copy(row[r:r+n], dst.Addr().AsSlice())
		binary.BigEndian.PutUint16(row[rp:], dst.Port())
		binary.LittleEndian.PutUint32(row[state:], 3)
	}
	return row
}
func ownerTable(rows ...[]byte) []byte {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, uint32(len(rows)))
	for _, r := range rows {
		b = append(b, r...)
	}
	return b
}
func TestOwnerTablesExactTupleAndAmbiguousUDP(t *testing.T) {
	for _, v6 := range []bool{false, true} {
		src, dst := netip.MustParseAddrPort("172.29.255.1:53000"), netip.MustParseAddrPort("198.18.1.1:443")
		wild := netip.MustParseAddrPort("0.0.0.0:53000")
		if v6 {
			src = netip.MustParseAddrPort("[fd04::1]:53000")
			dst = netip.MustParseAddrPort("[fd04::2]:443")
			wild = netip.MustParseAddrPort("[::]:53000")
		}
		tcp := ownerTable(ownerRow("tcp", v6, 123, src, dst))
		if pid, e := tableOwner(tcp, "tcp", v6, src, dst); e != nil || pid != 123 {
			t.Fatalf("SYN_SENT lookup: %d %v", pid, e)
		}
		if _, e := tableOwner(tcp, "tcp", v6, src, netip.AddrPortFrom(dst.Addr(), 80)); e == nil {
			t.Fatal("wrong destination accepted")
		}
		udp := ownerTable(ownerRow("udp", v6, 123, wild, dst))
		if pid, e := tableOwner(udp, "udp", v6, src, dst); e != nil || pid != 123 {
			t.Fatal("wildcard UDP lookup failed")
		}
		ambiguous := ownerTable(ownerRow("udp", v6, 123, wild, dst), ownerRow("udp", v6, 456, wild, dst))
		if _, e := tableOwner(ambiguous, "udp", v6, src, dst); e == nil {
			t.Fatal("ambiguous UDP owner guessed")
		}
		if _, e := tableOwner(tcp[:len(tcp)-1], "tcp", v6, src, dst); e == nil {
			t.Fatal("truncated table accepted")
		}
	}
}
