package main

import (
	"net/netip"
)

var refusedV4 = mustPrefixes(
	"0.0.0.0/8",
	"10.0.0.0/8",
	"100.64.0.0/10",
	"127.0.0.0/8",
	"169.254.0.0/16",
	"172.16.0.0/12",
	"192.0.0.0/24",
	"192.0.2.0/24",
	"192.168.0.0/16",
	"198.18.0.0/15",
	"198.51.100.0/24",
	"203.0.113.0/24",
	"224.0.0.0/4",
	"240.0.0.0/4",
)

var refusedV6 = mustPrefixes(
	"::/128",
	"::1/128",
	"fc00::/7",
	"fe80::/10",
	"ff00::/8",
	"64:ff9b::/32",
	"2001::/23",
	"2001:db8::/32",
)

var nat64 = netip.MustParsePrefix("64:ff9b::/96")

func mustPrefixes(literals ...string) []netip.Prefix {
	prefixes := make([]netip.Prefix, 0, len(literals))
	for _, literal := range literals {
		prefixes = append(prefixes, netip.MustParsePrefix(literal))
	}
	return prefixes
}

// isPublic reports whether address is on the public internet. Addresses inside
// the home network, the tailnet, or anywhere else only reachable locally are not.
func isPublic(address netip.Addr) bool {
	address = address.WithZone("")
	if embedded, ok := embeddedV4(address); ok {
		address = embedded
	}

	refused := refusedV6
	if address.Is4() {
		refused = refusedV4
	}
	for _, prefix := range refused {
		if prefix.Contains(address) {
			return false
		}
	}
	return true
}

func embeddedV4(address netip.Addr) (netip.Addr, bool) {
	if address.Is4() {
		return netip.Addr{}, false
	}
	if address.Is4In6() {
		return address.Unmap(), true
	}

	bytes := address.As16()
	switch {
	case bytes[0] == 0x20 && bytes[1] == 0x02:
		return netip.AddrFrom4([4]byte(bytes[2:6])), true
	case nat64.Contains(address):
		return netip.AddrFrom4([4]byte(bytes[12:16])), true
	case isZero(bytes[:12]):
		return netip.AddrFrom4([4]byte(bytes[12:16])), true
	}
	return netip.Addr{}, false
}

func isZero(bytes []byte) bool {
	for _, b := range bytes {
		if b != 0 {
			return false
		}
	}
	return true
}
