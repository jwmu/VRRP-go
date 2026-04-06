//go:build linux

package vrrp

import (
	"net"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

type heartbeatLinkUpdate struct {
	Name  string
	Index int
	Up    bool
}

func defaultHeartbeatSubscribe(ifaceName string, version byte, ch chan<- heartbeatLinkUpdate, done <-chan struct{}) error {
	link, err := netlink.LinkByName(ifaceName)
	if err != nil {
		return err
	}
	attrs := link.Attrs()
	if attrs == nil {
		return net.ErrClosed
	}
	index := attrs.Index

	linkCh := make(chan netlink.LinkUpdate, 8)
	if err := netlink.LinkSubscribe(linkCh, done); err != nil {
		return err
	}

	addrCh := make(chan netlink.AddrUpdate, 8)
	if err := netlink.AddrSubscribe(addrCh, done); err != nil {
		return err
	}

	state := newHeartbeatState(heartbeatLinkIsUp(attrs.Flags), heartbeatInterfaceHasGlobalUnicast(index, version))

	go func() {
		for {
			select {
			case update, ok := <-linkCh:
				if !ok {
					return
				}
				if int(update.Index) != index {
					continue
				}
				up := state.updateLink(heartbeatLinkUpdateIsUp(update))
				select {
				case ch <- heartbeatLinkUpdate{Name: ifaceName, Index: index, Up: up}:
				case <-done:
					return
				}
			case update, ok := <-addrCh:
				if !ok {
					return
				}
				if update.LinkIndex != index {
					continue
				}
				up := state.updateAddr(heartbeatInterfaceHasGlobalUnicast(index, version))
				select {
				case ch <- heartbeatLinkUpdate{Name: ifaceName, Index: index, Up: up}:
				case <-done:
					return
				}
			case <-done:
				return
			}
		}
	}()
	return nil
}

func heartbeatInterfaceHasGlobalUnicast(index int, version byte) bool {
	link, err := netlink.LinkByIndex(index)
	if err != nil {
		return false
	}

	family := netlink.FAMILY_ALL
	switch version {
	case IPv4:
		family = netlink.FAMILY_V4
	case IPv6:
		family = netlink.FAMILY_V6
	}

	addrs, err := netlink.AddrList(link, family)
	if err != nil {
		return false
	}
	for _, addr := range addrs {
		ip := addr.IP
		if ip == nil {
			ip = addr.IPNet.IP
		}
		if ip == nil {
			continue
		}
		if !heartbeatIPMatchesVersion(ip, version) {
			continue
		}
		if ip.IsGlobalUnicast() {
			return true
		}
	}
	return false
}

func heartbeatLinkUpdateIsUp(update netlink.LinkUpdate) bool {
	return heartbeatLinkIsUp(linkFlagsFromUpdate(update))
}

func heartbeatLinkIsUp(flags net.Flags) bool {
	return flags&net.FlagRunning != 0
}

func linkFlagsFromUpdate(update netlink.LinkUpdate) net.Flags {
	if update.Link != nil && update.Link.Attrs() != nil {
		return update.Link.Attrs().Flags
	}
	var flags net.Flags
	if update.Flags&unix.IFF_UP != 0 {
		flags |= net.FlagUp
	}
	if update.Flags&unix.IFF_BROADCAST != 0 {
		flags |= net.FlagBroadcast
	}
	if update.Flags&unix.IFF_LOOPBACK != 0 {
		flags |= net.FlagLoopback
	}
	if update.Flags&unix.IFF_POINTOPOINT != 0 {
		flags |= net.FlagPointToPoint
	}
	if update.Flags&unix.IFF_MULTICAST != 0 {
		flags |= net.FlagMulticast
	}
	if update.Flags&unix.IFF_RUNNING != 0 {
		flags |= net.FlagRunning
	}
	return flags
}
