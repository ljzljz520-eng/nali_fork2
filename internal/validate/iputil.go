package validate

import (
	"encoding/binary"
	"net"
)

func ipStringFromBytes(b []byte) string {
	return net.IP(b).String()
}

// parseProbe converts a textual probe address into the numeric index key of
// the database family (uint32 for IPv4, high-64-bits uint64 for IPv6).
func parseProbe[T uint32 | uint64](s string, v6 bool) (T, bool) {
	var zero T
	ip := net.ParseIP(s)
	if ip == nil {
		return zero, false
	}
	if v6 {
		ip6 := ip.To16()
		if ip6 == nil {
			return zero, false
		}
		return T(binary.BigEndian.Uint64(ip6[:8])), true
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return zero, false
	}
	return T(binary.BigEndian.Uint32(ip4)), true
}

func anchorIP[T uint32 | uint64](a anchor, v6 bool) (T, bool) {
	return parseProbe[T](a.ip, v6)
}
