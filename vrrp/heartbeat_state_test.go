package vrrp

import (
	"net"
	"testing"
)

func TestHeartbeatStateRequiresLinkAndAddress(t *testing.T) {
	state := newHeartbeatState(true, true)
	if !state.current() {
		t.Fatal("expected heartbeat to start up when link and address are both up")
	}

	if state.updateAddr(false) {
		t.Fatal("expected heartbeat to go down when address condition is false")
	}
	if state.updateLink(false) {
		t.Fatal("expected heartbeat to stay down when both conditions are false")
	}
	if state.updateAddr(true) {
		t.Fatal("expected heartbeat to stay down until link recovers")
	}
	if !state.updateLink(true) {
		t.Fatal("expected heartbeat to recover when link and address are both true")
	}
}

func TestHeartbeatHasGlobalUnicastAddressForVersion(t *testing.T) {
	ipv4Addrs := []net.Addr{
		&net.IPNet{IP: net.IPv4(127, 0, 0, 1), Mask: net.CIDRMask(8, 32)},
		&net.IPNet{IP: net.IPv4(10, 0, 0, 10), Mask: net.CIDRMask(24, 32)},
	}
	if !heartbeatHasGlobalUnicastAddressForVersion(ipv4Addrs, IPv4) {
		t.Fatal("expected IPv4 global unicast address to satisfy heartbeat")
	}
	if heartbeatHasGlobalUnicastAddressForVersion(ipv4Addrs, IPv6) {
		t.Fatal("did not expect IPv4 address list to satisfy IPv6 heartbeat")
	}

	ipv6Addrs := []net.Addr{
		&net.IPNet{IP: net.ParseIP("fe80::1"), Mask: net.CIDRMask(64, 128)},
		&net.IPNet{IP: net.ParseIP("2001:db8::10"), Mask: net.CIDRMask(64, 128)},
	}
	if !heartbeatHasGlobalUnicastAddressForVersion(ipv6Addrs, IPv6) {
		t.Fatal("expected IPv6 global unicast address to satisfy heartbeat")
	}
	if heartbeatHasGlobalUnicastAddressForVersion([]net.Addr{
		&net.IPNet{IP: net.ParseIP("fe80::1"), Mask: net.CIDRMask(64, 128)},
	}, IPv6) {
		t.Fatal("did not expect link-local IPv6 address to satisfy heartbeat")
	}
}
