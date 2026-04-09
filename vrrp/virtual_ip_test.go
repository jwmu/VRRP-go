package vrrp

import (
	"fmt"
	"net"
	"testing"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
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

func TestIsValidInterfaceName(t *testing.T) {
	tests := []struct {
		name  string
		valid bool
	}{
		{"eth0", true},
		{"ens3", true},
		{"vrrp-eth0", true},
		{"lo", true},
		{"a.b_c-d", true},
		{"", false},
		{"1234567890123456", false}, // 16 chars, too long
		{"123456789012345", true},   // 15 chars, ok
		{"eth0!", false},
		{"eth 0", false},
		{"eth/0", false},
	}
	for _, tt := range tests {
		got := isValidInterfaceName(tt.name)
		if got != tt.valid {
			t.Errorf("isValidInterfaceName(%q) = %v, want %v", tt.name, got, tt.valid)
		}
	}
}

func TestAddVirtualIPInvalidInterface(t *testing.T) {
	vr := &VirtualRouter{
		ipvX:             IPv4,
		protectedIPaddrs: make(map[[16]byte]*net.Interface),
		managedVIPs:      make(map[[16]byte]*managedVIP),
		managedVMACs:     make(map[string]string),
	}
	err := vr.AddVirtualIP("", "192.0.2.10/24")
	if err == nil {
		t.Fatal("expected error for empty interface name")
	}
}

func TestAddVirtualIPBadCIDR(t *testing.T) {
	vr := &VirtualRouter{
		ipvX:             IPv4,
		protectedIPaddrs: make(map[[16]byte]*net.Interface),
		managedVIPs:      make(map[[16]byte]*managedVIP),
		managedVMACs:     make(map[string]string),
	}
	err := vr.AddVirtualIP("eth0", "not-a-cidr")
	if err == nil {
		t.Fatal("expected error for invalid CIDR")
	}
}

func TestAddVirtualIPVersionMismatchIPv4(t *testing.T) {
	vr := &VirtualRouter{
		ipvX:             IPv4,
		protectedIPaddrs: make(map[[16]byte]*net.Interface),
		managedVIPs:      make(map[[16]byte]*managedVIP),
		managedVMACs:     make(map[string]string),
	}
	err := vr.AddVirtualIP("eth0", "2001:db8::1/64")
	if err == nil {
		t.Fatal("expected error for IPv6 address on IPv4 router")
	}
}

func TestAddVirtualIPVersionMismatchIPv6(t *testing.T) {
	vr := &VirtualRouter{
		ipvX:             IPv6,
		protectedIPaddrs: make(map[[16]byte]*net.Interface),
		managedVIPs:      make(map[[16]byte]*managedVIP),
		managedVMACs:     make(map[string]string),
	}
	err := vr.AddVirtualIP("eth0", "192.0.2.10/24")
	if err == nil {
		t.Fatal("expected error for IPv4 address on IPv6 router")
	}
}

func TestAddVirtualIPWithoutVMAC(t *testing.T) {
	ops := newFakeNetlinkOps()
	vr := &VirtualRouter{
		ipvX:             IPv4,
		useVMAC:          false,
		protectedIPaddrs: make(map[[16]byte]*net.Interface),
		managedVIPs:      make(map[[16]byte]*managedVIP),
		managedVMACs:     make(map[string]string),
		netlinkOps:       ops,
		interfaceByName: func(name string) (*net.Interface, error) {
			return &net.Interface{Name: name, Index: 100}, nil
		},
	}

	if err := vr.AddVirtualIP("eth0", "192.0.2.10/24"); err != nil {
		t.Fatalf("AddVirtualIP failed: %v", err)
	}
	if len(ops.linkAddCalls) != 0 {
		t.Fatal("expected no VMAC creation when useVMAC is false")
	}
	var key [16]byte
	copy(key[:], net.ParseIP("192.0.2.10").To16())
	if vr.managedVIPs[key] == nil {
		t.Fatal("expected managed VIP to be recorded")
	}
	if vr.managedVIPs[key].vmacName != "" {
		t.Fatal("expected vmacName to be empty when VMAC not used")
	}
}

func TestDestroyManagedVMACs(t *testing.T) {
	ops := newFakeNetlinkOps()
	ops.links["vrrp-eth1"] = &fakeLink{
		attrs: netlink.LinkAttrs{Name: "vrrp-eth1", Index: 11},
		kind:  "macvlan",
	}

	vr := &VirtualRouter{
		managedVMACs: map[string]string{"eth1": "vrrp-eth1"},
		netlinkOps:   ops,
	}

	if err := vr.destroyManagedVMACs(); err != nil {
		t.Fatalf("destroyManagedVMACs failed: %v", err)
	}
	if len(vr.managedVMACs) != 0 {
		t.Fatal("expected managed VMACs to be cleared")
	}
	if len(ops.linkDelCalls) != 1 || ops.linkDelCalls[0] != "vrrp-eth1" {
		t.Fatalf("expected VMAC to be deleted, got %v", ops.linkDelCalls)
	}
}

func TestDeleteMacvlanInterfaceNotFound(t *testing.T) {
	ops := newFakeNetlinkOps()
	// Deleting a non-existent interface should not error
	if err := deleteMacvlanInterface(ops, "nonexistent"); err != nil {
		t.Fatalf("deleteMacvlanInterface should not error for non-existent interface: %v", err)
	}
}

func TestCreateMacvlanInterfaceParentNotFound(t *testing.T) {
	ops := newFakeNetlinkOps()
	mac := net.HardwareAddr{0x00, 0x00, 0x5e, 0x00, 0x01, 0x01}
	err := createMacvlanInterface(ops, "vrrp-eth0", "eth0", mac)
	if err == nil {
		t.Fatal("expected error when parent interface not found")
	}
}

func TestCreateMacvlanInterfaceDeletesExisting(t *testing.T) {
	ops := newFakeNetlinkOps()
	ops.links["eth0"] = &fakeLink{
		attrs: netlink.LinkAttrs{Name: "eth0", Index: 1},
		kind:  "device",
	}
	// Pre-existing VMAC
	ops.links["vrrp-eth0"] = &fakeLink{
		attrs: netlink.LinkAttrs{Name: "vrrp-eth0", Index: 2},
		kind:  "macvlan",
	}

	mac := net.HardwareAddr{0x00, 0x00, 0x5e, 0x00, 0x01, 0x01}
	err := createMacvlanInterface(ops, "vrrp-eth0", "eth0", mac)
	if err != nil {
		t.Fatalf("createMacvlanInterface failed: %v", err)
	}
	// Should have deleted the existing one first
	found := false
	for _, name := range ops.linkDelCalls {
		if name == "vrrp-eth0" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected existing VMAC to be deleted before recreation")
	}
}

func TestSetUseVMACBeforeAddVirtualIP(t *testing.T) {
	vr := &VirtualRouter{
		managedVIPs: make(map[[16]byte]*managedVIP),
	}
	result := vr.SetUseVMAC(true)
	if result != vr {
		t.Fatal("expected SetUseVMAC to return receiver")
	}
	if !vr.UseVMAC() {
		t.Fatal("expected useVMAC to be true")
	}
}

func TestSetUseVMACAfterAddVirtualIPIgnored(t *testing.T) {
	ops := newFakeNetlinkOps()
	var key [16]byte
	copy(key[:], net.ParseIP("192.0.2.10").To16())
	vr := &VirtualRouter{
		ipvX:    IPv4,
		useVMAC: false,
		managedVIPs: map[[16]byte]*managedVIP{
			key: {cidr: "192.0.2.10/24"},
		},
		netlinkOps: ops,
	}
	vr.SetUseVMAC(true)
	if vr.UseVMAC() {
		t.Fatal("expected SetUseVMAC to be ignored when VIPs already exist")
	}
}

func TestActivateManagedVIPsLinkNotFound(t *testing.T) {
	ops := newFakeNetlinkOps()
	// No links registered
	var key [16]byte
	copy(key[:], net.ParseIP("192.0.2.10").To16())
	vr := &VirtualRouter{
		ipvX: IPv4,
		managedVIPs: map[[16]byte]*managedVIP{
			key: {cidr: "192.0.2.10/24", announceIface: "missing-iface"},
		},
		netlinkOps: ops,
	}
	err := vr.activateManagedVIPs()
	if err == nil {
		t.Fatal("expected error when announce interface not found")
	}
}

func TestDeactivateManagedVIPsLinkNotFound(t *testing.T) {
	ops := newFakeNetlinkOps()
	var key [16]byte
	copy(key[:], net.ParseIP("192.0.2.10").To16())
	vr := &VirtualRouter{
		ipvX: IPv4,
		managedVIPs: map[[16]byte]*managedVIP{
			key: {cidr: "192.0.2.10/24", announceIface: "missing-iface"},
		},
		netlinkOps: ops,
	}
	err := vr.deactivateManagedVIPs()
	if err == nil {
		t.Fatal("expected error when announce interface not found")
	}
}

func TestActivateManagedVIPsWithoutVMAC(t *testing.T) {
	ops := newFakeNetlinkOps()
	ops.links["eth0"] = &fakeLink{
		attrs: netlink.LinkAttrs{Name: "eth0", Index: 1},
		kind:  "device",
	}
	var key [16]byte
	copy(key[:], net.ParseIP("192.0.2.10").To16())
	vr := &VirtualRouter{
		ipvX: IPv4,
		managedVIPs: map[[16]byte]*managedVIP{
			key: {cidr: "192.0.2.10/24", parentIface: "eth0", announceIface: "eth0"},
		},
		netlinkOps: ops,
	}
	if err := vr.activateManagedVIPs(); err != nil {
		t.Fatalf("activateManagedVIPs failed: %v", err)
	}
	// Should NOT call LinkSetUp when vmacName is empty
	if len(ops.linkUpCalls) != 0 {
		t.Fatal("expected no LinkSetUp when vmacName is empty")
	}
	if len(ops.addrAddCalls) != 1 {
		t.Fatalf("expected 1 AddrAdd call, got %d", len(ops.addrAddCalls))
	}
}

func TestAddVirtualIPIPv6WithVMAC(t *testing.T) {
	ops := newFakeNetlinkOps()
	ops.links["eth1"] = &fakeLink{
		attrs: netlink.LinkAttrs{Name: "eth1", Index: 10},
		kind:  "device",
	}

	vr := &VirtualRouter{
		ipvX:                        IPv6,
		useVMAC:                     true,
		virtualRouterMACAddressIPv6: net.HardwareAddr{0x00, 0x00, 0x5e, 0x00, 0x02, 0x2a},
		protectedIPaddrs:            make(map[[16]byte]*net.Interface),
		managedVIPs:                 make(map[[16]byte]*managedVIP),
		managedVMACs:                make(map[string]string),
		netlinkOps:                  ops,
		interfaceByName: func(name string) (*net.Interface, error) {
			return &net.Interface{Name: name, Index: 100}, nil
		},
	}

	if err := vr.AddVirtualIP("eth1", "2001:db8::10/64"); err != nil {
		t.Fatalf("AddVirtualIP IPv6 failed: %v", err)
	}
	if len(ops.linkAddCalls) != 1 || ops.linkAddCalls[0] != "vrrp-eth1" {
		t.Fatalf("expected VMAC for IPv6, got %v", ops.linkAddCalls)
	}
}

func TestIgnoreAddrAddErrorFileExists(t *testing.T) {
	if !ignoreAddrAddError(unix.EEXIST) {
		t.Fatal("expected EEXIST to be ignored")
	}
	if ignoreAddrAddError(unix.EINVAL) {
		t.Fatal("expected EINVAL to not be ignored")
	}
}

func TestIgnoreAddrDelErrorNoSuchAddress(t *testing.T) {
	if !ignoreAddrDelError(unix.ENOENT) {
		t.Fatal("expected ENOENT to be ignored")
	}
	if ignoreAddrDelError(unix.EINVAL) {
		t.Fatal("expected EINVAL to not be ignored")
	}
}

func TestIgnoreAddrAddErrorContainsFileExists(t *testing.T) {
	err := fmt.Errorf("address add: file exists")
	if !ignoreAddrAddError(err) {
		t.Fatal("expected 'file exists' error string to be ignored")
	}
}

func TestIgnoreAddrDelErrorContainsExpectedStrings(t *testing.T) {
	tests := []struct {
		msg    string
		ignore bool
	}{
		{"cannot assign requested address", true},
		{"no such process", true},
		{"no such address", true},
		{"something else entirely", false},
	}
	for _, tt := range tests {
		err := fmt.Errorf("%s", tt.msg)
		if got := ignoreAddrDelError(err); got != tt.ignore {
			t.Errorf("ignoreAddrDelError(%q) = %v, want %v", tt.msg, got, tt.ignore)
		}
	}
}
