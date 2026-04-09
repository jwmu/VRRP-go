package vrrp

import (
	"net"
	"testing"
)

func TestPseudoHeaderToBytes(t *testing.T) {
	psh := &PseudoHeader{
		Saddr:    net.IPv4(10, 0, 0, 1).To16(),
		Daddr:    net.IPv4(224, 0, 0, 18).To16(),
		Zero:     0,
		Protocol: VRRPIPProtocolNumber,
		Len:      20,
	}
	b := psh.ToBytes()
	if len(b) != 36 {
		t.Fatalf("expected 36 bytes, got %d", len(b))
	}
	if b[33] != VRRPIPProtocolNumber {
		t.Fatalf("expected protocol %d, got %d", VRRPIPProtocolNumber, b[33])
	}
}

func TestPacketVersionRoundTrip(t *testing.T) {
	var pkt VRRPPacket
	pkt.SetVersion(VRRPv3)
	if pkt.GetVersion() != byte(VRRPv3) {
		t.Fatalf("expected version %d, got %d", VRRPv3, pkt.GetVersion())
	}
	pkt.SetVersion(VRRPv2)
	if pkt.GetVersion() != byte(VRRPv2) {
		t.Fatalf("expected version %d, got %d", VRRPv2, pkt.GetVersion())
	}
}

func TestPacketTypeRoundTrip(t *testing.T) {
	var pkt VRRPPacket
	pkt.SetType()
	if pkt.GetType() != 1 {
		t.Fatalf("expected type 1, got %d", pkt.GetType())
	}
}

func TestPacketVirtualRouterIDRoundTrip(t *testing.T) {
	var pkt VRRPPacket
	pkt.SetVirtualRouterID(42)
	if pkt.GetVirtualRouterID() != 42 {
		t.Fatalf("expected VRID 42, got %d", pkt.GetVirtualRouterID())
	}
}

func TestPacketPriorityRoundTrip(t *testing.T) {
	var pkt VRRPPacket
	pkt.SetPriority(200)
	if pkt.GetPriority() != 200 {
		t.Fatalf("expected priority 200, got %d", pkt.GetPriority())
	}
}

func TestPacketIPvXAddrCountRoundTrip(t *testing.T) {
	var pkt VRRPPacket
	pkt.setIPvXAddrCount(5)
	if pkt.GetIPvXAddrCount() != 5 {
		t.Fatalf("expected count 5, got %d", pkt.GetIPvXAddrCount())
	}
}

func TestPacketAdvertisementIntervalRoundTrip(t *testing.T) {
	var pkt VRRPPacket
	pkt.SetAdvertisementInterval(300)
	if pkt.GetAdvertisementInterval() != 300 {
		t.Fatalf("expected interval 300, got %d", pkt.GetAdvertisementInterval())
	}
	// Test max 12-bit value
	pkt.SetAdvertisementInterval(4095)
	if pkt.GetAdvertisementInterval() != 4095 {
		t.Fatalf("expected interval 4095, got %d", pkt.GetAdvertisementInterval())
	}
}

func TestPacketVersionAndTypePreserveEachOther(t *testing.T) {
	var pkt VRRPPacket
	pkt.SetVersion(VRRPv3)
	pkt.SetType()
	if pkt.GetVersion() != byte(VRRPv3) {
		t.Fatal("SetType should not clobber version")
	}
	if pkt.GetType() != 1 {
		t.Fatal("SetVersion should not clobber type after SetType")
	}
}

func TestAddIPv4AddrAndGetIPvXAddr(t *testing.T) {
	var pkt VRRPPacket
	ip := net.IPv4(192, 168, 1, 10).To16()
	pkt.AddIPvXAddr(IPv4, ip)
	if pkt.GetIPvXAddrCount() != 1 {
		t.Fatalf("expected 1 address, got %d", pkt.GetIPvXAddrCount())
	}
	addrs := pkt.GetIPvXAddr(IPv4)
	if len(addrs) != 1 {
		t.Fatalf("expected 1 address, got %d", len(addrs))
	}
	expected := net.IPv4(192, 168, 1, 10).To4()
	if !addrs[0].Equal(expected) {
		t.Fatalf("expected %v, got %v", expected, addrs[0])
	}
}

func TestAddMultipleIPv4Addrs(t *testing.T) {
	var pkt VRRPPacket
	ips := []net.IP{
		net.IPv4(10, 0, 0, 1).To16(),
		net.IPv4(10, 0, 0, 2).To16(),
		net.IPv4(10, 0, 0, 3).To16(),
	}
	for _, ip := range ips {
		pkt.AddIPvXAddr(IPv4, ip)
	}
	if pkt.GetIPvXAddrCount() != 3 {
		t.Fatalf("expected 3 addresses, got %d", pkt.GetIPvXAddrCount())
	}
	addrs := pkt.GetIPvXAddr(IPv4)
	if len(addrs) != 3 {
		t.Fatalf("expected 3 addresses, got %d", len(addrs))
	}
}

func TestAddIPv6AddrAndGetIPvXAddr(t *testing.T) {
	var pkt VRRPPacket
	ip := net.ParseIP("2001:db8::1")
	pkt.AddIPvXAddr(IPv6, ip)
	if pkt.GetIPvXAddrCount() != 1 {
		t.Fatalf("expected 1 address, got %d", pkt.GetIPvXAddrCount())
	}
	addrs := pkt.GetIPvXAddr(IPv6)
	if len(addrs) != 1 {
		t.Fatalf("expected 1 address, got %d", len(addrs))
	}
	if !addrs[0].Equal(ip) {
		t.Fatalf("expected %v, got %v", ip, addrs[0])
	}
}

func TestAddIPvXAddrMaxCountIgnored(t *testing.T) {
	var pkt VRRPPacket
	pkt.setIPvXAddrCount(255)
	ip := net.IPv4(10, 0, 0, 1).To16()
	pkt.AddIPvXAddr(IPv4, ip)
	if pkt.GetIPvXAddrCount() != 255 {
		t.Fatal("expected add to be rejected at max count")
	}
}

func TestAddIPvXAddrPanicsOnBadVersion(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic for unsupported IP version")
		}
	}()
	var pkt VRRPPacket
	pkt.AddIPvXAddr(99, net.IPv4(10, 0, 0, 1).To16())
}

func TestToBytesRoundTrip(t *testing.T) {
	var pkt VRRPPacket
	pkt.SetVersion(VRRPv3)
	pkt.SetType()
	pkt.SetVirtualRouterID(42)
	pkt.SetPriority(150)
	pkt.SetAdvertisementInterval(100)
	pkt.AddIPvXAddr(IPv4, net.IPv4(192, 0, 2, 10).To16())

	b := pkt.ToBytes()
	if len(b) != 12 { // 8 header + 4 (one IPv4 addr)
		t.Fatalf("expected 12 bytes, got %d", len(b))
	}
}

func TestFromBytesIPv4(t *testing.T) {
	var pkt VRRPPacket
	pkt.SetVersion(VRRPv3)
	pkt.SetType()
	pkt.SetVirtualRouterID(42)
	pkt.SetPriority(150)
	pkt.SetAdvertisementInterval(100)
	pkt.AddIPvXAddr(IPv4, net.IPv4(192, 0, 2, 10).To16())
	pkt.AddIPvXAddr(IPv4, net.IPv4(192, 0, 2, 20).To16())

	b := pkt.ToBytes()
	parsed, err := FromBytes(IPv4, b)
	if err != nil {
		t.Fatalf("FromBytes failed: %v", err)
	}
	if parsed.GetVersion() != byte(VRRPv3) {
		t.Fatalf("expected version %d, got %d", VRRPv3, parsed.GetVersion())
	}
	if parsed.GetVirtualRouterID() != 42 {
		t.Fatalf("expected VRID 42, got %d", parsed.GetVirtualRouterID())
	}
	if parsed.GetPriority() != 150 {
		t.Fatalf("expected priority 150, got %d", parsed.GetPriority())
	}
	if parsed.GetIPvXAddrCount() != 2 {
		t.Fatalf("expected 2 addresses, got %d", parsed.GetIPvXAddrCount())
	}
	addrs := parsed.GetIPvXAddr(IPv4)
	if len(addrs) != 2 {
		t.Fatalf("expected 2 addresses, got %d", len(addrs))
	}
}

func TestFromBytesIPv6(t *testing.T) {
	var pkt VRRPPacket
	pkt.SetVersion(VRRPv3)
	pkt.SetType()
	pkt.SetVirtualRouterID(10)
	pkt.SetPriority(200)
	pkt.AddIPvXAddr(IPv6, net.ParseIP("2001:db8::1"))

	b := pkt.ToBytes()
	parsed, err := FromBytes(IPv6, b)
	if err != nil {
		t.Fatalf("FromBytes failed: %v", err)
	}
	if parsed.GetIPvXAddrCount() != 1 {
		t.Fatalf("expected 1 address, got %d", parsed.GetIPvXAddrCount())
	}
	addrs := parsed.GetIPvXAddr(IPv6)
	if len(addrs) != 1 {
		t.Fatalf("expected 1 address, got %d", len(addrs))
	}
	expected := net.ParseIP("2001:db8::1")
	if !addrs[0].Equal(expected) {
		t.Fatalf("expected %v, got %v", expected, addrs[0])
	}
}

func TestFromBytesTooShort(t *testing.T) {
	_, err := FromBytes(IPv4, []byte{1, 2, 3})
	if err == nil {
		t.Fatal("expected error for short packet")
	}
}

func TestFromBytesBadIPVersion(t *testing.T) {
	b := make([]byte, 8)
	_, err := FromBytes(99, b)
	if err == nil {
		t.Fatal("expected error for bad IP version")
	}
}

func TestFromBytesAddrCountMismatch(t *testing.T) {
	b := make([]byte, 8)
	b[3] = 5 // claim 5 addresses, but only have 8 bytes total
	_, err := FromBytes(IPv4, b)
	if err == nil {
		t.Fatal("expected error for addr count mismatch")
	}
}

func TestFromBytesWithExtraData(t *testing.T) {
	// VRRP v2 packets may have auth data appended; FromBytes should ignore extra bytes
	var pkt VRRPPacket
	pkt.SetVersion(VRRPv2)
	pkt.SetType()
	pkt.SetVirtualRouterID(1)
	pkt.SetPriority(100)
	pkt.AddIPvXAddr(IPv4, net.IPv4(10, 0, 0, 1).To16())
	b := pkt.ToBytes()
	// Append extra auth data
	b = append(b, 0, 0, 0, 0, 0, 0, 0, 0)
	parsed, err := FromBytes(IPv4, b)
	if err != nil {
		t.Fatalf("FromBytes with extra data failed: %v", err)
	}
	if parsed.GetIPvXAddrCount() != 1 {
		t.Fatalf("expected 1 address, got %d", parsed.GetIPvXAddrCount())
	}
}

func TestChecksumSetAndValidate(t *testing.T) {
	var pkt VRRPPacket
	pkt.SetVersion(VRRPv3)
	pkt.SetType()
	pkt.SetVirtualRouterID(42)
	pkt.SetPriority(100)
	pkt.SetAdvertisementInterval(100)
	pkt.AddIPvXAddr(IPv4, net.IPv4(192, 0, 2, 10).To16())

	pshdr := &PseudoHeader{
		Saddr:    net.IPv4(10, 0, 0, 1).To16(),
		Daddr:    net.IPv4(224, 0, 0, 18).To16(),
		Protocol: VRRPIPProtocolNumber,
		Len:      uint16(len(pkt.ToBytes())),
	}
	pkt.SetCheckSum(pshdr)

	if pkt.GetCheckSum() == 0 {
		t.Fatal("expected non-zero checksum")
	}
	if !pkt.ValidateCheckSum(pshdr) {
		t.Fatal("checksum validation failed")
	}

	// Corrupt the packet and verify validation fails
	pkt.SetPriority(200)
	if pkt.ValidateCheckSum(pshdr) {
		t.Fatal("expected corrupted packet to fail checksum validation")
	}
}

func TestChecksumDifferentSrcDst(t *testing.T) {
	var pkt VRRPPacket
	pkt.SetVersion(VRRPv3)
	pkt.SetType()
	pkt.SetVirtualRouterID(42)
	pkt.SetPriority(100)
	pkt.AddIPvXAddr(IPv4, net.IPv4(192, 0, 2, 10).To16())

	pshdr1 := &PseudoHeader{
		Saddr:    net.IPv4(10, 0, 0, 1).To16(),
		Daddr:    net.IPv4(224, 0, 0, 18).To16(),
		Protocol: VRRPIPProtocolNumber,
		Len:      uint16(len(pkt.ToBytes())),
	}
	pkt.SetCheckSum(pshdr1)
	checksum1 := pkt.GetCheckSum()

	pshdr2 := &PseudoHeader{
		Saddr:    net.IPv4(10, 0, 0, 2).To16(),
		Daddr:    net.IPv4(224, 0, 0, 18).To16(),
		Protocol: VRRPIPProtocolNumber,
		Len:      uint16(len(pkt.ToBytes())),
	}
	pkt.SetCheckSum(pshdr2)
	checksum2 := pkt.GetCheckSum()

	if checksum1 == checksum2 {
		t.Fatal("expected different checksums for different source addresses")
	}
}

func TestGetIPvXAddrEmptyPacket(t *testing.T) {
	var pkt VRRPPacket
	addrs := pkt.GetIPvXAddr(IPv4)
	if len(addrs) != 0 {
		t.Fatalf("expected 0 addresses, got %d", len(addrs))
	}
	addrs = pkt.GetIPvXAddr(IPv6)
	if len(addrs) != 0 {
		t.Fatalf("expected 0 addresses for IPv6, got %d", len(addrs))
	}
}

func TestChecksumIPv6(t *testing.T) {
	var pkt VRRPPacket
	pkt.SetVersion(VRRPv3)
	pkt.SetType()
	pkt.SetVirtualRouterID(42)
	pkt.SetPriority(100)
	pkt.AddIPvXAddr(IPv6, net.ParseIP("2001:db8::1"))

	pshdr := &PseudoHeader{
		Saddr:    net.ParseIP("2001:db8::100"),
		Daddr:    VRRPMultiAddrIPv6,
		Protocol: VRRPIPProtocolNumber,
		Len:      uint16(len(pkt.ToBytes())),
	}
	pkt.SetCheckSum(pshdr)

	if pkt.GetCheckSum() == 0 {
		t.Fatal("expected non-zero IPv6 checksum")
	}
	if !pkt.ValidateCheckSum(pshdr) {
		t.Fatal("IPv6 checksum validation failed")
	}
}
