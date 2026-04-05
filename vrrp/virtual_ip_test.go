package vrrp

import (
	"fmt"
	"net"
	"testing"

	"github.com/vishvananda/netlink"
)

type fakeLink struct {
	attrs netlink.LinkAttrs
	kind  string
}

func (l *fakeLink) Attrs() *netlink.LinkAttrs { return &l.attrs }
func (l *fakeLink) Type() string              { return l.kind }

type fakeNetlinkOps struct {
	links         map[string]*fakeLink
	linkAddCalls  []string
	linkDelCalls  []string
	linkUpCalls   []string
	linkDownCalls []string
	addrAddCalls  []string
	addrDelCalls  []string
}

func newFakeNetlinkOps() *fakeNetlinkOps {
	return &fakeNetlinkOps{
		links: make(map[string]*fakeLink),
	}
}

func (f *fakeNetlinkOps) LinkByName(name string) (netlink.Link, error) {
	link, ok := f.links[name]
	if !ok {
		return nil, fmt.Errorf("link %s not found", name)
	}
	return link, nil
}

func (f *fakeNetlinkOps) LinkAdd(link netlink.Link) error {
	attrs := *link.Attrs()
	f.links[attrs.Name] = &fakeLink{attrs: attrs, kind: link.Type()}
	f.linkAddCalls = append(f.linkAddCalls, attrs.Name)
	return nil
}

func (f *fakeNetlinkOps) LinkDel(link netlink.Link) error {
	name := link.Attrs().Name
	delete(f.links, name)
	f.linkDelCalls = append(f.linkDelCalls, name)
	return nil
}

func (f *fakeNetlinkOps) LinkSetHardwareAddr(link netlink.Link, mac net.HardwareAddr) error {
	link.Attrs().HardwareAddr = mac
	return nil
}

func (f *fakeNetlinkOps) LinkSetUp(link netlink.Link) error {
	f.linkUpCalls = append(f.linkUpCalls, link.Attrs().Name)
	return nil
}

func (f *fakeNetlinkOps) LinkSetDown(link netlink.Link) error {
	f.linkDownCalls = append(f.linkDownCalls, link.Attrs().Name)
	return nil
}

func (f *fakeNetlinkOps) AddrAdd(link netlink.Link, addr *netlink.Addr) error {
	f.addrAddCalls = append(f.addrAddCalls, link.Attrs().Name+"="+addr.String())
	return nil
}

func (f *fakeNetlinkOps) AddrDel(link netlink.Link, addr *netlink.Addr) error {
	f.addrDelCalls = append(f.addrDelCalls, link.Attrs().Name+"="+addr.String())
	return nil
}

func (f *fakeNetlinkOps) ParseAddr(cidr string) (*netlink.Addr, error) {
	return netlink.ParseAddr(cidr)
}

func TestAddVirtualIPWithVMACCreatesMacvlanAndTracksProtectedIP(t *testing.T) {
	ops := newFakeNetlinkOps()
	ops.links["eth1"] = &fakeLink{
		attrs: netlink.LinkAttrs{Name: "eth1", Index: 10},
		kind:  "device",
	}

	vr := &VirtualRouter{
		ipvX:                        IPv4,
		useVMAC:                     true,
		virtualRouterMACAddressIPv4: net.HardwareAddr{0x00, 0x00, 0x5e, 0x00, 0x01, 0x2a},
		protectedIPaddrs:            make(map[[16]byte]*net.Interface),
		managedVIPs:                 make(map[[16]byte]*managedVIP),
		managedVMACs:                make(map[string]string),
		netlinkOps:                  ops,
		interfaceByName: func(name string) (*net.Interface, error) {
			return &net.Interface{Name: name, Index: 100}, nil
		},
	}

	if err := vr.AddVirtualIP("eth1", "192.0.2.10/24"); err != nil {
		t.Fatalf("AddVirtualIP failed: %v", err)
	}

	if len(ops.linkAddCalls) != 1 || ops.linkAddCalls[0] != "vrrp-eth1" {
		t.Fatalf("expected VMAC interface to be created once, got %v", ops.linkAddCalls)
	}

	var key [16]byte
	copy(key[:], net.ParseIP("192.0.2.10").To16())
	if vr.managedVIPs[key] == nil {
		t.Fatal("managed VIP entry was not recorded")
	}
	if vr.managedVIPs[key].announceIface != "vrrp-eth1" {
		t.Fatalf("expected managed VIP to announce on vrrp-eth1, got %s", vr.managedVIPs[key].announceIface)
	}
	if vr.protectedIPaddrs[key] == nil || vr.protectedIPaddrs[key].Name != "vrrp-eth1" {
		t.Fatal("protected IP was not associated with the VMAC interface")
	}
}

func TestManagedVIPActivationAndDeactivationUseAnnounceInterface(t *testing.T) {
	ops := newFakeNetlinkOps()
	ops.links["vrrp-eth1"] = &fakeLink{
		attrs: netlink.LinkAttrs{Name: "vrrp-eth1", Index: 11},
		kind:  "macvlan",
	}

	var key [16]byte
	copy(key[:], net.ParseIP("192.0.2.10").To16())
	vr := &VirtualRouter{
		ipvX:         IPv4,
		useVMAC:      true,
		managedVIPs:  make(map[[16]byte]*managedVIP),
		managedVMACs: map[string]string{"eth1": "vrrp-eth1"},
		netlinkOps:   ops,
	}
	vr.managedVIPs[key] = &managedVIP{
		cidr:          "192.0.2.10/24",
		parentIface:   "eth1",
		announceIface: "vrrp-eth1",
		vmacName:      "vrrp-eth1",
	}

	if err := vr.activateManagedVIPs(); err != nil {
		t.Fatalf("activateManagedVIPs failed: %v", err)
	}
	if len(ops.linkUpCalls) != 1 || ops.linkUpCalls[0] != "vrrp-eth1" {
		t.Fatalf("expected VMAC link set up, got %v", ops.linkUpCalls)
	}
	if len(ops.addrAddCalls) != 1 || ops.addrAddCalls[0] != "vrrp-eth1=192.0.2.10/24" {
		t.Fatalf("expected VIP added to announce interface, got %v", ops.addrAddCalls)
	}

	if err := vr.deactivateManagedVIPs(); err != nil {
		t.Fatalf("deactivateManagedVIPs failed: %v", err)
	}
	if len(ops.addrDelCalls) != 1 || ops.addrDelCalls[0] != "vrrp-eth1=192.0.2.10/24" {
		t.Fatalf("expected VIP removed from announce interface, got %v", ops.addrDelCalls)
	}
	if len(ops.linkDownCalls) != 1 || ops.linkDownCalls[0] != "vrrp-eth1" {
		t.Fatalf("expected VMAC link set down, got %v", ops.linkDownCalls)
	}
}
