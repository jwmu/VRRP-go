package vrrp

import (
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/jwmu/VRRP-go/logger"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

const ifaFNoprefixroute = 0x200

type managedVIP struct {
	cidr          string
	parentIface   string
	announceIface string
	vmacName      string
}

type netlinkOps interface {
	LinkByName(string) (netlink.Link, error)
	LinkAdd(netlink.Link) error
	LinkDel(netlink.Link) error
	LinkSetHardwareAddr(netlink.Link, net.HardwareAddr) error
	LinkSetUp(netlink.Link) error
	LinkSetDown(netlink.Link) error
	AddrAdd(netlink.Link, *netlink.Addr) error
	AddrDel(netlink.Link, *netlink.Addr) error
	ParseAddr(string) (*netlink.Addr, error)
}

type systemNetlinkOps struct{}

func (systemNetlinkOps) LinkByName(name string) (netlink.Link, error) {
	return netlink.LinkByName(name)
}
func (systemNetlinkOps) LinkAdd(link netlink.Link) error { return netlink.LinkAdd(link) }
func (systemNetlinkOps) LinkDel(link netlink.Link) error { return netlink.LinkDel(link) }
func (systemNetlinkOps) LinkSetHardwareAddr(link netlink.Link, mac net.HardwareAddr) error {
	return netlink.LinkSetHardwareAddr(link, mac)
}
func (systemNetlinkOps) LinkSetUp(link netlink.Link) error   { return netlink.LinkSetUp(link) }
func (systemNetlinkOps) LinkSetDown(link netlink.Link) error { return netlink.LinkSetDown(link) }
func (systemNetlinkOps) AddrAdd(link netlink.Link, addr *netlink.Addr) error {
	return netlink.AddrAdd(link, addr)
}
func (systemNetlinkOps) AddrDel(link netlink.Link, addr *netlink.Addr) error {
	return netlink.AddrDel(link, addr)
}
func (systemNetlinkOps) ParseAddr(cidr string) (*netlink.Addr, error) { return netlink.ParseAddr(cidr) }

func (r *VirtualRouter) SetUseVMAC(enabled bool) *VirtualRouter {
	if len(r.managedVIPs) > 0 {
		logger.GLoger.Printf(logger.ERROR, "SetUseVMAC: must be called before AddVirtualIP")
		return r
	}
	r.useVMAC = enabled
	return r
}

func (r *VirtualRouter) UseVMAC() bool {
	return r.useVMAC
}

func isValidInterfaceName(name string) bool {
	if len(name) == 0 || len(name) > 15 {
		return false
	}
	for _, c := range name {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '.' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

func (r *VirtualRouter) AddVirtualIP(iface, cidr string) error {
	if !isValidInterfaceName(iface) {
		return fmt.Errorf("VirtualRouter.AddVirtualIP: invalid interface name %s", iface)
	}
	ip, _, err := net.ParseCIDR(cidr)
	if err != nil {
		return fmt.Errorf("VirtualRouter.AddVirtualIP: parse %s: %v", cidr, err)
	}

	if r.ipvX == IPv4 && ip.To4() == nil {
		return fmt.Errorf("VirtualRouter.AddVirtualIP: %s is not IPv4", cidr)
	}
	if r.ipvX == IPv6 && ip.To4() != nil {
		return fmt.Errorf("VirtualRouter.AddVirtualIP: %s is not IPv6", cidr)
	}

	announceIface := iface
	vmacName := ""
	if r.useVMAC {
		vmacName = "vrrp-" + iface
		if _, ok := r.managedVMACs[iface]; !ok {
			vmacMAC := r.virtualRouterMACAddressIPv4
			if r.ipvX == IPv6 {
				vmacMAC = r.virtualRouterMACAddressIPv6
			}
			if err := createMacvlanInterface(r.netlinkOps, vmacName, iface, vmacMAC); err != nil {
				return err
			}
			r.managedVMACs[iface] = vmacName
		}
		announceIface = vmacName
	}

	if err := r.AddIPvXAddr(announceIface, ip); err != nil {
		return err
	}

	var key [16]byte
	copy(key[:], ip.To16())
	r.managedVIPs[key] = &managedVIP{
		cidr:          cidr,
		parentIface:   iface,
		announceIface: announceIface,
		vmacName:      vmacName,
	}
	return nil
}

func (r *VirtualRouter) activateManagedVIPs() error {
	var errs []error
	for key, vip := range r.managedVIPs {
		link, err := r.netlinkOps.LinkByName(vip.announceIface)
		if err != nil {
			errs = append(errs, fmt.Errorf("activate %v: link %s: %v", net.IP(key[:]), vip.announceIface, err))
			continue
		}
		if vip.vmacName != "" {
			if err := r.netlinkOps.LinkSetUp(link); err != nil {
				errs = append(errs, fmt.Errorf("activate %v: set up %s: %v", net.IP(key[:]), vip.announceIface, err))
				continue
			}
		}
		addr, err := r.netlinkOps.ParseAddr(vip.cidr)
		if err != nil {
			errs = append(errs, fmt.Errorf("activate %v: parse %s: %v", net.IP(key[:]), vip.cidr, err))
			continue
		}
		addr.Flags |= ifaFNoprefixroute
		if err := r.netlinkOps.AddrAdd(link, addr); err != nil && !ignoreAddrAddError(err) {
			errs = append(errs, fmt.Errorf("activate %v on %s: %v", net.IP(key[:]), vip.announceIface, err))
		}
	}
	return errors.Join(errs...)
}

func (r *VirtualRouter) deactivateManagedVIPs() error {
	var errs []error
	for key, vip := range r.managedVIPs {
		link, err := r.netlinkOps.LinkByName(vip.announceIface)
		if err != nil {
			errs = append(errs, fmt.Errorf("deactivate %v: link %s: %v", net.IP(key[:]), vip.announceIface, err))
			continue
		}
		addr, err := r.netlinkOps.ParseAddr(vip.cidr)
		if err != nil {
			errs = append(errs, fmt.Errorf("deactivate %v: parse %s: %v", net.IP(key[:]), vip.cidr, err))
			continue
		}
		if err := r.netlinkOps.AddrDel(link, addr); err != nil && !ignoreAddrDelError(err) {
			errs = append(errs, fmt.Errorf("deactivate %v on %s: %v", net.IP(key[:]), vip.announceIface, err))
		}
		if vip.vmacName != "" {
			if err := r.netlinkOps.LinkSetDown(link); err != nil {
				errs = append(errs, fmt.Errorf("deactivate %v: set down %s: %v", net.IP(key[:]), vip.announceIface, err))
			}
		}
	}
	return errors.Join(errs...)
}

func (r *VirtualRouter) destroyManagedVMACs() error {
	var errs []error
	for parentIface, vmacName := range r.managedVMACs {
		if err := deleteMacvlanInterface(r.netlinkOps, vmacName); err != nil {
			errs = append(errs, fmt.Errorf("destroy VMAC %s for %s: %v", vmacName, parentIface, err))
		}
		delete(r.managedVMACs, parentIface)
	}
	return errors.Join(errs...)
}

func createMacvlanInterface(ops netlinkOps, name, parent string, mac net.HardwareAddr) error {
	parentLink, err := ops.LinkByName(parent)
	if err != nil {
		return fmt.Errorf("createMacvlanInterface: failed to find parent interface %s: %v", parent, err)
	}

	existingLink, err := ops.LinkByName(name)
	if err == nil {
		if err := ops.LinkDel(existingLink); err != nil {
			logger.GLoger.Printf(logger.ERROR, "createMacvlanInterface: failed to delete existing interface %s: %v", name, err)
		}
	}

	macvlanLink := &netlink.Macvlan{
		LinkAttrs: netlink.LinkAttrs{
			Name:         name,
			ParentIndex:  parentLink.Attrs().Index,
			HardwareAddr: mac,
		},
		Mode: netlink.MACVLAN_MODE_BRIDGE,
	}
	if err := ops.LinkAdd(macvlanLink); err != nil {
		return fmt.Errorf("createMacvlanInterface: failed to create macvlan interface %s: %v", name, err)
	}

	link, err := ops.LinkByName(name)
	if err != nil {
		return fmt.Errorf("createMacvlanInterface: failed to get created link %s: %v", name, err)
	}

	if err := ops.LinkSetHardwareAddr(link, mac); err != nil {
		_ = ops.LinkDel(link)
		return fmt.Errorf("createMacvlanInterface: failed to set MAC address for %s: %v", name, err)
	}
	return nil
}

func deleteMacvlanInterface(ops netlinkOps, name string) error {
	link, err := ops.LinkByName(name)
	if err != nil {
		return nil
	}
	if err := ops.LinkDel(link); err != nil {
		return fmt.Errorf("deleteMacvlanInterface: failed to delete macvlan interface %s: %v", name, err)
	}
	return nil
}

func ignoreAddrAddError(err error) bool {
	return errors.Is(err, unix.EEXIST) || strings.Contains(err.Error(), "file exists")
}

func ignoreAddrDelError(err error) bool {
	return errors.Is(err, unix.ENOENT) ||
		strings.Contains(err.Error(), "cannot assign requested address") ||
		strings.Contains(err.Error(), "no such process") ||
		strings.Contains(err.Error(), "no such address")
}
