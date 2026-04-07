package utils

import "net/netip"

func IsValidIP(input string) bool {
	addr, err := netip.ParseAddr(input)
	return err == nil && addr.IsValid()
}
