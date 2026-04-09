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

func TestNewHeartbeatStateStartsDown(t *testing.T) {
	state := newHeartbeatState(false, false)
	if state.current() {
		t.Fatal("expected heartbeat to start down when both conditions are false")
	}
}

func TestHeartbeatStateLinkOnlyIsNotEnough(t *testing.T) {
	state := newHeartbeatState(true, false)
	if state.current() {
		t.Fatal("expected heartbeat down with link up but no address")
	}
}

func TestHeartbeatStateAddrOnlyIsNotEnough(t *testing.T) {
	state := newHeartbeatState(false, true)
	if state.current() {
		t.Fatal("expected heartbeat down with address up but no link")
	}
}

func TestHeartbeatHasGlobalUnicastWithIPAddr(t *testing.T) {
	// Test with *net.IPAddr type
	addrs := []net.Addr{
		&net.IPAddr{IP: net.IPv4(10, 0, 0, 1)},
	}
	if !heartbeatHasGlobalUnicastAddressForVersion(addrs, IPv4) {
		t.Fatal("expected *net.IPAddr with global unicast to satisfy heartbeat")
	}
}

func TestHeartbeatHasGlobalUnicastWithIPAddrIPv6(t *testing.T) {
	addrs := []net.Addr{
		&net.IPAddr{IP: net.ParseIP("2001:db8::1")},
	}
	if !heartbeatHasGlobalUnicastAddressForVersion(addrs, IPv6) {
		t.Fatal("expected IPv6 *net.IPAddr to satisfy heartbeat")
	}
	if heartbeatHasGlobalUnicastAddressForVersion(addrs, IPv4) {
		t.Fatal("did not expect IPv6 *net.IPAddr to satisfy IPv4 heartbeat")
	}
}

func TestHeartbeatHasGlobalUnicastEmptyList(t *testing.T) {
	if heartbeatHasGlobalUnicastAddressForVersion(nil, IPv4) {
		t.Fatal("expected nil addresses to return false")
	}
	if heartbeatHasGlobalUnicastAddressForVersion([]net.Addr{}, IPv4) {
		t.Fatal("expected empty addresses to return false")
	}
}

func TestHeartbeatIPMatchesVersionUnknown(t *testing.T) {
	if heartbeatIPMatchesVersion(net.IPv4(10, 0, 0, 1), 99) {
		t.Fatal("expected unknown version to return false")
	}
}

func TestHeartbeatIPMatchesVersionIPv4(t *testing.T) {
	if !heartbeatIPMatchesVersion(net.IPv4(10, 0, 0, 1), IPv4) {
		t.Fatal("expected IPv4 address to match IPv4")
	}
	if heartbeatIPMatchesVersion(net.ParseIP("2001:db8::1"), IPv4) {
		t.Fatal("expected IPv6 address to not match IPv4")
	}
}

func TestHeartbeatIPMatchesVersionIPv6(t *testing.T) {
	if !heartbeatIPMatchesVersion(net.ParseIP("2001:db8::1"), IPv6) {
		t.Fatal("expected IPv6 address to match IPv6")
	}
	if heartbeatIPMatchesVersion(net.IPv4(10, 0, 0, 1), IPv6) {
		t.Fatal("expected IPv4 address to not match IPv6")
	}
}

// stringAddr implements net.Addr for testing the fallback parser path.
type stringAddr struct {
	s string
}

func (a stringAddr) Network() string { return "test" }
func (a stringAddr) String() string  { return a.s }

func TestHeartbeatHasGlobalUnicastFallbackParser(t *testing.T) {
	// Test the default branch of the type switch that uses net.ParseCIDR
	addrs := []net.Addr{
		stringAddr{s: "10.0.0.1/24"},
	}
	if !heartbeatHasGlobalUnicastAddressForVersion(addrs, IPv4) {
		t.Fatal("expected fallback parser to find global unicast IPv4")
	}
}

func TestHeartbeatHasGlobalUnicastFallbackParserBadInput(t *testing.T) {
	addrs := []net.Addr{
		stringAddr{s: "not-an-ip"},
	}
	if heartbeatHasGlobalUnicastAddressForVersion(addrs, IPv4) {
		t.Fatal("expected bad input to return false")
	}
}
