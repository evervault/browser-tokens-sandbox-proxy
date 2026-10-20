package main

import (
	"net/netip"
	"testing"
)

func assertPermits(t *testing.T, want bool, literals ...string) {
	t.Helper()
	for _, literal := range literals {
		if got := isPublic(netip.MustParseAddr(literal)); got != want {
			t.Errorf("isPublic(%s) = %v, want %v", literal, got, want)
		}
	}
}

func TestRoutableAddressesArePermitted(t *testing.T) {
	assertPermits(t, true,
		"1.1.1.1", "8.8.8.8", "93.184.216.34", "172.32.0.1", "100.63.255.255",
		"100.128.0.1", "198.20.0.1", "2606:4700:4700::1111", "2001:db9::1",
	)
}

func TestLoopbackIsRefused(t *testing.T) {
	assertPermits(t, false, "127.0.0.1", "127.1.2.3", "::1")
}

func TestPrivateRangesAreRefused(t *testing.T) {
	assertPermits(t, false,
		"10.0.0.1", "10.255.255.255", "172.16.0.1", "172.31.255.255",
		"192.168.1.1", "192.168.0.254", "fd00::1", "fc00::1",
	)
}

func TestLinkLocalIsRefused(t *testing.T) {
	assertPermits(t, false, "169.254.169.254", "169.254.0.1", "fe80::1", "fe80::1%eth0")
}

func TestTailnetAddressesAreRefused(t *testing.T) {
	assertPermits(t, false, "100.64.0.1", "100.100.100.100", "100.127.255.255", "fd7a:115c:a1e0::1")
}

func TestUnroutedRangesAreRefused(t *testing.T) {
	assertPermits(t, false,
		"0.0.0.0", "0.1.2.3", "198.18.0.1", "240.0.0.1", "255.255.255.255",
		"224.0.0.1", "192.0.2.1", "192.0.0.170", "::", "ff02::1",
		"2001:db8::1", "2001::1", "64:ff9b:1::1",
	)
}

func TestV4SpelledAsV6IsJudgedAsV4(t *testing.T) {
	assertPermits(t, false, "::ffff:127.0.0.1", "::ffff:192.168.1.1", "::ffff:10.0.0.1")
	assertPermits(t, true, "::ffff:1.1.1.1")
}

func TestV4CarriedBy6to4OrNat64IsJudgedAsV4(t *testing.T) {
	assertPermits(t, false, "2002:c0a8:0101::", "2002:7f00:1::", "64:ff9b::c0a8:101", "64:ff9b::7f00:1")
	assertPermits(t, true, "2002:0101:0101::", "64:ff9b::0808:0808")
}
