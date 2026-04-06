package vrrp

import (
	"fmt"
	"net"
	"net/netip"
	"sync"

	"github.com/jwmu/VRRP-go/logger"

	"github.com/mdlayher/arp"
	"github.com/mdlayher/ndp"

	"syscall"
	"time"
)

type IPConnection interface {
	WriteMessage(*VRRPPacket) error
	WriteMessageTo(*VRRPPacket, net.IP) error // Write message to a specific unicast address
	ReadMessage() (*VRRPPacket, error)
	Close() error
}

type AddrAnnouncer interface {
	AnnounceAll(vr *VirtualRouter) error
	Close() error
}

type arpClient interface {
	WriteTo(*arp.Packet, net.HardwareAddr) error
	Close() error
}

type arpInterfaceSender struct {
	mu               sync.Mutex
	client           arpClient
	throttleInterval time.Duration
	queue            chan *arp.Packet
	closed           bool
	wg               sync.WaitGroup
}

type IPv4AddrAnnouncer struct {
	mu      sync.Mutex
	senders map[int]*arpInterfaceSender
}

type IPv6AddrAnnouncer struct {
	ndpConns map[int]*ndp.Conn
}

func newARPInterfaceSender(client arpClient, throttleInterval time.Duration) *arpInterfaceSender {
	sender := &arpInterfaceSender{
		client:           client,
		throttleInterval: throttleInterval,
		queue:            make(chan *arp.Packet, 64),
	}
	sender.wg.Add(1)
	go sender.run()
	return sender
}

func (s *arpInterfaceSender) run() {
	defer s.wg.Done()
	var lastSent time.Time
	for packet := range s.queue {
		throttleInterval := s.getThrottleInterval()
		if !lastSent.IsZero() && throttleInterval > 0 {
			if wait := throttleInterval - time.Since(lastSent); wait > 0 {
				time.Sleep(wait)
			}
		}
		err := s.client.WriteTo(packet, BroaddcastHADDR)
		if err == nil {
			lastSent = time.Now()
		}
	}
}

func (s *arpInterfaceSender) enqueue(packet *arp.Packet) error {
	s.mu.Lock()

	if s.closed {
		s.mu.Unlock()
		err := fmt.Errorf("arpInterfaceSender.enqueue: sender closed")
		return err
	}
	s.mu.Unlock()
	s.queue <- packet
	return nil
}

func (s *arpInterfaceSender) setThrottleInterval(interval time.Duration) {
	s.mu.Lock()
	s.throttleInterval = interval
	s.mu.Unlock()
}

func (s *arpInterfaceSender) getThrottleInterval() time.Duration {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.throttleInterval
}

func (s *arpInterfaceSender) close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	close(s.queue)
	s.mu.Unlock()

	s.wg.Wait()
	return s.client.Close()
}

func NewIPIPv6AddrAnnouncer() *IPv6AddrAnnouncer {
	announcer := &IPv6AddrAnnouncer{
		ndpConns: make(map[int]*ndp.Conn),
	}
	return announcer
}

func (nd *IPv6AddrAnnouncer) getConnForInterface(iface *net.Interface) (*ndp.Conn, error) {
	if iface == nil {
		return nil, fmt.Errorf("IPv6AddrAnnouncer.getConnForInterface: nil interface provided")
	}
	if conn, ok := nd.ndpConns[iface.Index]; ok {
		return conn, nil
	}
	con, ip, err := ndp.Listen(iface, ndp.LinkLocal)
	if err != nil {
		return nil, fmt.Errorf("IPv6AddrAnnouncer.getConnForInterface: %v", err)
	}
	nd.ndpConns[iface.Index] = con
	logger.GLoger.Printf(logger.INFO, "NDP client initialized, working on %v, source IP %v", iface.Name, ip)
	return con, nil
}

func (nd *IPv6AddrAnnouncer) AnnounceAll(vr *VirtualRouter) error {
	for key, iface := range vr.protectedIPaddrs {
		if iface == nil {
			logger.GLoger.Printf(logger.ERROR, "IPv6AddrAnnouncer.AnnounceAll: interface missing for IP %v", net.IP(key[:]))
			return fmt.Errorf("IPv6AddrAnnouncer.AnnounceAll: interface missing for IP %v", net.IP(key[:]))
		}
		address := netip.AddrFrom16(key)
		multicastgroup, errOfParseMulticastGroup := ndp.SolicitedNodeMulticast(address)
		if errOfParseMulticastGroup != nil {
			logger.GLoger.Printf(logger.ERROR, "IPv6AddrAnnouncer.AnnounceAll: %v", errOfParseMulticastGroup)
			return errOfParseMulticastGroup
		}
		conn, err := nd.getConnForInterface(iface)
		if err != nil {
			logger.GLoger.Printf(logger.ERROR, "IPv6AddrAnnouncer.AnnounceAll: %v", err)
			return err
		}
		msg := &ndp.NeighborAdvertisement{
			Override:      true,
			TargetAddress: address,
			Options: []ndp.Option{
				&ndp.LinkLayerAddress{
					Direction: ndp.Source,
					Addr:      iface.HardwareAddr,
				},
			},
		}
		if errOfWrite := conn.WriteTo(msg, nil, multicastgroup); errOfWrite != nil {
			logger.GLoger.Printf(logger.ERROR, "IPv6AddrAnnouncer.AnnounceAll: %v", errOfWrite)
			return errOfWrite
		}
		logger.GLoger.Printf(logger.INFO, "send unsolicited neighbor advertisement for %v via %s", net.IP(key[:]), iface.Name)
	}

	return nil
}

func (nd *IPv6AddrAnnouncer) Close() error {
	var firstErr error
	for index, conn := range nd.ndpConns {
		if err := conn.Close(); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("IPv6AddrAnnouncer.Close: interface %d: %v", index, err)
		}
		delete(nd.ndpConns, index)
	}
	return firstErr
}

// makeGratuitousPacket builds a gratuitous ARP packet for the requested operation.
func (ar *IPv4AddrAnnouncer) makeGratuitousPacket(address netip.Addr, hardwareAddr net.HardwareAddr, operation GratuitousARPOperation) (*arp.Packet, error) {
	var packet arp.Packet
	packet.HardwareType = 1      //ethernet10m
	packet.ProtocolType = 0x0800 //IPv4
	packet.HardwareAddrLength = 6
	packet.IPLength = 4
	packet.SenderHardwareAddr = hardwareAddr
	packet.SenderIP = address
	packet.TargetHardwareAddr = BroaddcastHADDR
	packet.TargetIP = address

	switch operation {
	case GratuitousARPRequest:
		packet.Operation = arp.OperationRequest
	case GratuitousARPReply:
		packet.Operation = arp.OperationReply
	default:
		return nil, fmt.Errorf("IPv4AddrAnnouncer.makeGratuitousPacket: unsupported gratuitous ARP operation %d", operation)
	}

	return &packet, nil
}

// AnnounceAll sends the configured gratuitous ARP operation for all protected IPv4 addresses.
func (ar *IPv4AddrAnnouncer) AnnounceAll(vr *VirtualRouter) error {
	for k, iface := range vr.protectedIPaddrs {
		if iface == nil {
			logger.GLoger.Printf(logger.ERROR, "IPv4AddrAnnouncer.AnnounceAll: interface missing for IP %v", net.IP(k[:]))
			return fmt.Errorf("IPv4AddrAnnouncer.AnnounceAll: interface missing for IP %v", net.IP(k[:]))
		}
		sender, err := ar.getSenderForInterface(iface, vr.garpThrottleInterval)
		if err != nil {
			logger.GLoger.Printf(logger.ERROR, "IPv4AddrAnnouncer.AnnounceAll: %v", err)
			return err
		}

		address := netip.AddrFrom4(netip.AddrFrom16(k).As4())
		for i := 0; i < vr.garpMasterRepeat; i++ {
			packet, err := ar.makeGratuitousPacket(address, iface.HardwareAddr, vr.garpOperation)
			if err != nil {
				return err
			}
			err = sender.enqueue(packet)
			if err != nil {
				return err
			}
		}
		logger.GLoger.Printf(logger.INFO, "send gratuitous %s arp for %v via %s", vr.garpOperation, net.IP(k[:]), iface.Name)
	}
	return nil
}

func NewIPv4AddrAnnouncer() *IPv4AddrAnnouncer {
	announcer := &IPv4AddrAnnouncer{
		senders: make(map[int]*arpInterfaceSender),
	}
	return announcer
}

func (ar *IPv4AddrAnnouncer) Close() error {
	ar.mu.Lock()
	senders := make([]*arpInterfaceSender, 0, len(ar.senders))
	for index, sender := range ar.senders {
		senders = append(senders, sender)
		delete(ar.senders, index)
	}
	ar.mu.Unlock()

	var firstErr error
	for _, sender := range senders {
		if err := sender.close(); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("IPv4AddrAnnouncer.Close: %v", err)
		}
	}
	return firstErr
}

func (ar *IPv4AddrAnnouncer) getSenderForInterface(iface *net.Interface, throttleInterval time.Duration) (*arpInterfaceSender, error) {
	if iface == nil {
		return nil, fmt.Errorf("IPv4AddrAnnouncer.getSenderForInterface: nil interface provided")
	}
	ar.mu.Lock()
	if sender, ok := ar.senders[iface.Index]; ok {
		sender.setThrottleInterval(throttleInterval)
		ar.mu.Unlock()
		return sender, nil
	}
	ar.mu.Unlock()

	client, err := arp.Dial(iface)
	if err != nil {
		return nil, fmt.Errorf("IPv4AddrAnnouncer.getSenderForInterface: %v", err)
	}
	logger.GLoger.Printf(logger.DEBUG, "IPv4AddrAnnouncer: initialized ARP client on interface %s", iface.Name)
	sender := newARPInterfaceSender(client, throttleInterval)

	ar.mu.Lock()
	if existing, ok := ar.senders[iface.Index]; ok {
		existing.setThrottleInterval(throttleInterval)
		ar.mu.Unlock()
		if err := sender.close(); err != nil {
			logger.GLoger.Printf(logger.ERROR, "IPv4AddrAnnouncer.getSenderForInterface: close redundant sender on %s: %v", iface.Name, err)
		}
		return existing, nil
	}
	ar.senders[iface.Index] = sender
	ar.mu.Unlock()
	return sender, nil
}

type IPv4Con struct {
	buffer     []byte
	remote     net.IP
	local      net.IP
	SendCon    *net.IPConn
	ReceiveCon *net.IPConn
	isUnicast  bool
	closeOnce  sync.Once
}

type IPv6Con struct {
	buffer    []byte
	oob       []byte
	remote    net.IP
	local     net.IP
	Con       *net.IPConn
	isUnicast bool
	closeOnce sync.Once
}

func ipConnection(local, remote net.IP) (*net.IPConn, error) {

	var conn *net.IPConn
	var errOfListenIP error
	//redundant
	//todo simplify here
	if local.IsLinkLocalUnicast() {
		var itf, errOfFind = findInterfacebyIP(local)
		if errOfFind != nil {
			return nil, fmt.Errorf("ipConnection: can't find zone info of %v", local)
		}
		conn, errOfListenIP = net.ListenIP("ip:112", &net.IPAddr{IP: local, Zone: itf.Name})
	} else {
		conn, errOfListenIP = net.ListenIP("ip:112", &net.IPAddr{IP: local})
	}
	if errOfListenIP != nil {
		return nil, errOfListenIP
	}
	var fd, errOfGetFD = conn.File()
	if errOfGetFD != nil {
		return nil, errOfGetFD
	}
	defer fd.Close()
	if remote.To4() != nil {
		//IPv4 mode
		//set hop limit
		if errOfSetHopLimit := syscall.SetsockoptInt(int(fd.Fd()), syscall.IPPROTO_IP, syscall.IP_MULTICAST_TTL, VRRPMultiTTL); errOfSetHopLimit != nil {
			return nil, fmt.Errorf("ipConnection: %v", errOfSetHopLimit)
		}
		//set tos
		if errOfSetTOS := syscall.SetsockoptInt(int(fd.Fd()), syscall.IPPROTO_IP, syscall.IP_TOS, 7); errOfSetTOS != nil {
			return nil, fmt.Errorf("ipConnection: %v", errOfSetTOS)
		}
		//disable multicast loop
		if errOfSetLoop := syscall.SetsockoptInt(int(fd.Fd()), syscall.IPPROTO_IP, syscall.IP_MULTICAST_LOOP, 0); errOfSetLoop != nil {
			return nil, fmt.Errorf("ipConnection: %v", errOfSetLoop)
		}
	} else {
		//IPv6 mode
		//set hop limit
		if errOfSetHOPLimit := syscall.SetsockoptInt(int(fd.Fd()), syscall.IPPROTO_IPV6, syscall.IPV6_MULTICAST_HOPS, 255); errOfSetHOPLimit != nil {
			return nil, fmt.Errorf("ipConnection: %v", errOfSetHOPLimit)
		}
		//disable multicast loop
		if errOfSetLoop := syscall.SetsockoptInt(int(fd.Fd()), syscall.IPPROTO_IPV6, syscall.IPV6_MULTICAST_LOOP, 0); errOfSetLoop != nil {
			return nil, fmt.Errorf("ipConnection: %v", errOfSetLoop)
		}
		//to receive the hop limit and dst address in oob
		if err := syscall.SetsockoptInt(int(fd.Fd()), syscall.IPPROTO_IPV6, syscall.IPV6_2292HOPLIMIT, 1); err != nil {
			return nil, fmt.Errorf("ipConnection: %v", err)
		}
		if err := syscall.SetsockoptInt(int(fd.Fd()), syscall.IPPROTO_IPV6, syscall.IPV6_2292PKTINFO, 1); err != nil {
			return nil, fmt.Errorf("ipConnection: %v", err)
		}

	}
	logger.GLoger.Printf(logger.INFO, "IP virtual connection established %v ==> %v", local, remote)
	return conn, nil
}

func makeMulticastIPv4Conn(multi, local net.IP) (*net.IPConn, error) {
	var conn, errOfListenIP = net.ListenIP("ip4:112", &net.IPAddr{IP: multi})
	if errOfListenIP != nil {
		return nil, fmt.Errorf("makeMulticastIPv4Conn: %v", errOfListenIP)
	}
	var fd, errOfGetFD = conn.File()
	if errOfGetFD != nil {
		return nil, fmt.Errorf("makeMulticastIPv4Conn: %v", errOfGetFD)
	}
	defer fd.Close()
	multi = multi.To4()
	local = local.To4()
	var mreq = &syscall.IPMreq{
		Multiaddr: [4]byte{multi[0], multi[1], multi[2], multi[3]},
		Interface: [4]byte{local[0], local[1], local[2], local[3]},
	}
	if errSetMreq := syscall.SetsockoptIPMreq(int(fd.Fd()), syscall.IPPROTO_IP, syscall.IP_ADD_MEMBERSHIP, mreq); errSetMreq != nil {
		return nil, fmt.Errorf("makeMulticastIPv4Conn: %v", errSetMreq)
	}
	return conn, nil
}

func joinIPv6MulticastGroup(con *net.IPConn, local, remote net.IP) error {
	var fd, errOfGetFD = con.File()
	if errOfGetFD != nil {
		return fmt.Errorf("joinIPv6MulticastGroup: %v", errOfGetFD)
	}
	defer fd.Close()
	var mreq = &syscall.IPv6Mreq{}
	copy(mreq.Multiaddr[:], remote.To16())
	var IF, errOfGetIF = findInterfacebyIP(local)
	if errOfGetIF != nil {
		return fmt.Errorf("joinIPv6MulticastGroup: %v", errOfGetIF)
	}
	mreq.Interface = uint32(IF.Index)
	if errOfSetMreq := syscall.SetsockoptIPv6Mreq(int(fd.Fd()), syscall.IPPROTO_IPV6, syscall.IPV6_JOIN_GROUP, mreq); errOfSetMreq != nil {
		return fmt.Errorf("joinIPv6MulticastGroup: %v", errOfSetMreq)
	}
	logger.GLoger.Printf(logger.INFO, "Join IPv6 multicast group %v on %v", remote, IF.Name)
	return nil
}

func NewIPv4ConnMulticast(local, remote net.IP) (IPConnection, error) {
	SendConn, err := ipConnection(local, remote)
	if err != nil {
		return nil, err
	}
	receiveConn, err := makeMulticastIPv4Conn(VRRPMultiAddrIPv4, local)
	if err != nil {
		SendConn.Close()
		return nil, err
	}
	return &IPv4Con{
		buffer:     make([]byte, 2048),
		local:      local,
		remote:     remote,
		SendCon:    SendConn,
		ReceiveCon: receiveConn,
		isUnicast:  false,
	}, nil

}

func NewIPv4ConnUnicast(local, remote net.IP) (IPConnection, error) {
	sendConn, err := ipConnection(local, remote)
	if err != nil {
		return nil, err
	}
	reveiveConn, err := net.ListenIP("ip4:112", &net.IPAddr{IP: net.IPv4zero})
	if err != nil {
		sendConn.Close()
		return nil, err
	}
	return &IPv4Con{
		buffer:     make([]byte, 2048),
		local:      local,
		remote:     remote,
		SendCon:    sendConn,
		ReceiveCon: reveiveConn,
		isUnicast:  true,
	}, nil
}

func (conn *IPv4Con) WriteMessage(packet *VRRPPacket) error {
	if _, err := conn.SendCon.WriteTo(packet.ToBytes(), &net.IPAddr{IP: conn.remote}); err != nil {
		return fmt.Errorf("IPv4Con.WriteMessage: %v", err)
	}
	return nil
}

func (conn *IPv4Con) WriteMessageTo(packet *VRRPPacket, dest net.IP) error {
	if _, err := conn.SendCon.WriteTo(packet.ToBytes(), &net.IPAddr{IP: dest}); err != nil {
		return fmt.Errorf("IPv4Con.WriteMessageTo: %v", err)
	}
	return nil
}

func (conn *IPv4Con) ReadMessage() (*VRRPPacket, error) {
	var n, errOfRead = conn.ReceiveCon.Read(conn.buffer)
	if errOfRead != nil {
		return nil, fmt.Errorf("IPv4Con.ReadMessage: %v", errOfRead)
	}
	if n < 20 {
		return nil, fmt.Errorf("IPv4Con.ReadMessage: IP datagram lenght %v too small", n)
	}
	var hdrlen = (int(conn.buffer[0]) & 0x0f) << 2
	if hdrlen > n {
		return nil, fmt.Errorf("IPv4Con.ReadMessage: the header length %v is larger than total length %v", hdrlen, n)
	}
	if (!conn.isUnicast) && conn.buffer[8] != 255 {
		return nil, fmt.Errorf("IPv4Con.ReadMessage: the TTL of IP datagram carring VRRP advertisment must equal to 255")
	}
	if advertisement, errOfUnmarshal := FromBytes(IPv4, conn.buffer[hdrlen:n]); errOfUnmarshal != nil {
		return nil, fmt.Errorf("IPv4Con.ReadMessage: %v", errOfUnmarshal)
	} else {
		if VRRPVersion(advertisement.GetVersion()) != VRRPv3 {
			return nil, fmt.Errorf("IPv4Con.ReadMessage: received an advertisement with %s", VRRPVersion(advertisement.GetVersion()))
		}
		var pshdr PseudoHeader
		pshdr.Saddr = net.IPv4(conn.buffer[12], conn.buffer[13], conn.buffer[14], conn.buffer[15]).To16()
		pshdr.Daddr = net.IPv4(conn.buffer[16], conn.buffer[17], conn.buffer[18], conn.buffer[19]).To16()
		pshdr.Protocol = VRRPIPProtocolNumber
		pshdr.Len = uint16(n - hdrlen)
		if !advertisement.ValidateCheckSum(&pshdr) {
			return nil, fmt.Errorf("IPv4Con.ReadMessage: validate the check sum of advertisement failed")
		} else {
			advertisement.Pshdr = &pshdr
			return advertisement, nil
		}
	}
}

func (conn *IPv4Con) Close() error {
	var firstErr error
	conn.closeOnce.Do(func() {
		if conn.SendCon != nil {
			if err := conn.SendCon.Close(); err != nil && firstErr == nil {
				firstErr = fmt.Errorf("IPv4Con.Close: send connection: %v", err)
			}
		}
		if conn.ReceiveCon != nil {
			if err := conn.ReceiveCon.Close(); err != nil && firstErr == nil {
				firstErr = fmt.Errorf("IPv4Con.Close: receive connection: %v", err)
			}
		}
	})
	return firstErr
}

func NewIPv6ConMulticast(local, remote net.IP) (IPConnection, error) {
	con, err := ipConnection(local, remote)
	if err != nil {
		return nil, err
	}
	if err := joinIPv6MulticastGroup(con, local, remote); err != nil {
		con.Close()
		return nil, err
	}
	return &IPv6Con{
		buffer: make([]byte, 4096),
		oob:    make([]byte, 4096),
		local:  local,
		remote: remote,
		Con:    con,
	}, nil
}

func NewIPv6ConUnicast(local, remote net.IP) (IPConnection, error) {
	con, err := ipConnection(local, remote)
	if err != nil {
		return nil, err
	}
	return &IPv6Con{
		buffer:    make([]byte, 4096),
		oob:       make([]byte, 4096),
		local:     local,
		remote:    remote,
		Con:       con,
		isUnicast: true,
	}, nil
}

func (con *IPv6Con) WriteMessage(packet *VRRPPacket) error {
	if _, errOfWrite := con.Con.WriteToIP(packet.ToBytes(), &net.IPAddr{IP: con.remote}); errOfWrite != nil {
		return fmt.Errorf("IPv6Con.WriteMessage: %v", errOfWrite)
	}
	return nil
}

func (con *IPv6Con) WriteMessageTo(packet *VRRPPacket, dest net.IP) error {
	if _, errOfWrite := con.Con.WriteToIP(packet.ToBytes(), &net.IPAddr{IP: dest}); errOfWrite != nil {
		return fmt.Errorf("IPv6Con.WriteMessageTo: %v", errOfWrite)
	}
	return nil
}

func (con *IPv6Con) ReadMessage() (*VRRPPacket, error) {
	var buffern, oobn, _, raddr, errOfRead = con.Con.ReadMsgIP(con.buffer, con.oob)
	if errOfRead != nil {
		return nil, fmt.Errorf("IPv6Con.ReadMessage: %v", errOfRead)
	}
	var oobdata, errOfParseOOB = syscall.ParseSocketControlMessage(con.oob[:oobn])
	if errOfParseOOB != nil {
		return nil, fmt.Errorf("IPv6Con.ReadMessage: %v", errOfParseOOB)
	}
	var (
		dst    net.IP
		TTL    byte
		GetTTL = false
	)
	for index := range oobdata {
		if oobdata[index].Header.Level != syscall.IPPROTO_IPV6 {
			continue
		}
		switch oobdata[index].Header.Type {
		case syscall.IPV6_2292HOPLIMIT:
			if len(oobdata[index].Data) == 0 {
				return nil, fmt.Errorf("IPv6Con.ReadMessage: invalid HOPLIMIT")
			}
			TTL = oobdata[index].Data[0]
			GetTTL = true
		case syscall.IPV6_2292PKTINFO:
			if len(oobdata[index].Data) < 16 {
				return nil, fmt.Errorf("IPv6Con.ReadMessage: invalid destination IP addrress length")
			}
			dst = net.IP(oobdata[index].Data[:16])
		}
	}
	if GetTTL == false {
		return nil, fmt.Errorf("IPv6Con.ReadMessage: HOPLIMIT not found")
	}
	if dst == nil {
		return nil, fmt.Errorf("IPv6Con.ReadMessage: destination address not found")
	}
	var pshdr = PseudoHeader{
		Daddr:    dst,
		Saddr:    raddr.IP,
		Protocol: VRRPIPProtocolNumber,
		Len:      uint16(buffern),
	}
	var advertisement, errOfUnmarshal = FromBytes(IPv6, con.buffer)
	if errOfUnmarshal != nil {
		return nil, fmt.Errorf("IPv6Con.ReadMessage: %v", errOfUnmarshal)
	}
	if TTL != 255 {
		return nil, fmt.Errorf("IPv6Con.ReadMessage: invalid HOPLIMIT")
	}
	if VRRPVersion(advertisement.GetVersion()) != VRRPv3 {
		return nil, fmt.Errorf("IPv6Con.ReadMessage: invalid VRRP version %v", advertisement.GetVersion())
	}
	if !advertisement.ValidateCheckSum(&pshdr) {
		return nil, fmt.Errorf("IPv6Con.ReadMessage: invalid check sum")
	}
	advertisement.Pshdr = &pshdr
	return advertisement, nil
}

func (con *IPv6Con) Close() error {
	var firstErr error
	con.closeOnce.Do(func() {
		if con.Con != nil {
			if err := con.Con.Close(); err != nil {
				firstErr = fmt.Errorf("IPv6Con.Close: %v", err)
			}
		}
	})
	return firstErr
}

func findIPbyInterface(itf *net.Interface, IPvX byte) (net.IP, error) {
	var addrs, errOfListAddrs = itf.Addrs()
	if errOfListAddrs != nil {
		return nil, fmt.Errorf("findIPbyInterface: %v", errOfListAddrs)
	}
	for index := range addrs {
		var ipaddr, _, errOfParseIP = net.ParseCIDR(addrs[index].String())
		if errOfParseIP != nil {
			return nil, fmt.Errorf("findIPbyInterface: %v", errOfParseIP)
		}
		if IPvX == IPv4 {
			if ipaddr.To4() != nil {
				if ipaddr.IsGlobalUnicast() {
					return ipaddr, nil
				}
			}
		} else {
			if ipaddr.To4() == nil {
				if ipaddr.IsLinkLocalUnicast() {
					return ipaddr, nil
				}
			}
		}
	}
	return nil, fmt.Errorf("findIPbyInterface: can not find valid IP addrs on %v", itf.Name)
}

func findInterfacebyIP(ip net.IP) (*net.Interface, error) {
	if itfs, errOfListInterface := net.Interfaces(); errOfListInterface != nil {
		return nil, fmt.Errorf("findInterfacebyIP: %v", errOfListInterface)
	} else {
		for index := range itfs {
			if addrs, errOfListAddrs := itfs[index].Addrs(); errOfListAddrs != nil {
				return nil, fmt.Errorf("findInterfacebyIP: %v", errOfListAddrs)
			} else {
				for index1 := range addrs {
					var ipaddr, _, errOfParseIP = net.ParseCIDR(addrs[index1].String())
					if errOfParseIP != nil {
						return nil, fmt.Errorf("findInterfacebyIP: %v", errOfParseIP)
					}
					if ipaddr.Equal(ip) {
						return &itfs[index], nil
					}
				}
			}
		}
	}

	return nil, fmt.Errorf("findInterfacebyIP: can't find the corresponding interface of %v", ip)
}
