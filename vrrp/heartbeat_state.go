package vrrp

import "net"

type heartbeatState struct {
	linkUp bool
	addrUp bool
}

func newHeartbeatState(linkUp, addrUp bool) heartbeatState {
	return heartbeatState{
		linkUp: linkUp,
		addrUp: addrUp,
	}
}

func (s *heartbeatState) updateLink(up bool) bool {
	s.linkUp = up
	return s.current()
}

func (s *heartbeatState) updateAddr(up bool) bool {
	s.addrUp = up
	return s.current()
}

func (s heartbeatState) current() bool {
	return s.linkUp && s.addrUp
}

func heartbeatHasGlobalUnicastAddressForVersion(addrs []net.Addr, version byte) bool {
	for _, addr := range addrs {
		switch value := addr.(type) {
		case *net.IPNet:
			if heartbeatIPMatchesVersion(value.IP, version) && value.IP.IsGlobalUnicast() {
				return true
			}
		case *net.IPAddr:
			if heartbeatIPMatchesVersion(value.IP, version) && value.IP.IsGlobalUnicast() {
				return true
			}
		default:
			ip, _, err := net.ParseCIDR(addr.String())
			if err != nil {
				continue
			}
			if heartbeatIPMatchesVersion(ip, version) && ip.IsGlobalUnicast() {
				return true
			}
		}
	}
	return false
}

func heartbeatIPMatchesVersion(ip net.IP, version byte) bool {
	switch version {
	case IPv4:
		return ip.To4() != nil
	case IPv6:
		return ip.To4() == nil && ip.To16() != nil
	default:
		return false
	}
}
