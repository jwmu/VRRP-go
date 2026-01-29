package vrrp

import (
	"fmt"
	"net"
	"time"

	"github.com/jwmu/VRRP-go/logger"
)

type VirtualRouter struct {
	vrID                          byte
	priority                      byte
	advertisementInterval         uint16
	advertisementIntervalOfMaster uint16
	skewTime                      uint16
	masterDownInterval            uint16
	preempt                       bool
	owner                         bool
	virtualRouterMACAddressIPv4   net.HardwareAddr
	virtualRouterMACAddressIPv6   net.HardwareAddr
	//
	unicastMode  bool
	unicastPeers []net.IP // Unicast peer addresses for RFC 5798 unicast mode
	//
	netInterface        *net.Interface
	ipvX                byte
	preferredSourceIP   net.IP
	protectedIPaddrs    map[[16]byte]*net.Interface
	state               int
	iplayerInterface    IPConnection
	ipAddrAnnouncer     AddrAnnouncer
	eventChannel        chan EVENT
	packetQueue         chan *VRRPPacket
	advertisementTicker *time.Ticker
	masterDownTimer     *time.Timer
	transitionHandler   map[transition]func()
}

// NewVirtualRouter create a new virtual router with designated parameters
func NewVirtualRouter(VRID byte, nif string, Owner bool, IPvX byte) *VirtualRouter {
	if IPvX != IPv4 && IPvX != IPv6 {
		logger.GLoger.Printf(logger.FATAL, "NewVirtualRouter: parameter IPvx must be IPv4 or IPv6")
	}
	var vr = &VirtualRouter{}
	vr.vrID = VRID
	// RFC 5798 / RFC 3768: Virtual MAC address format
	// IPv4: 00-00-5E-00-01-{VRID}
	// IPv6: 00-00-5E-00-02-{VRID}
	// The last byte should be the VRID value (0-255)
	vr.virtualRouterMACAddressIPv4, _ = net.ParseMAC(fmt.Sprintf("00-00-5E-00-01-%02X", VRID))
	vr.virtualRouterMACAddressIPv6, _ = net.ParseMAC(fmt.Sprintf("00-00-5E-00-02-%02X", VRID))
	vr.owner = Owner
	//default values that defined by RFC 5798
	if Owner {
		vr.priority = 255
	}
	vr.state = INIT
	vr.preempt = defaultPreempt
	vr.SetAdvInterval(defaultAdvertisementInterval)
	vr.SetPriorityAndMasterAdvInterval(defaultPriority, defaultAdvertisementInterval)

	//make
	vr.protectedIPaddrs = make(map[[16]byte]*net.Interface)
	vr.unicastPeers = make([]net.IP, 0)
	vr.eventChannel = make(chan EVENT, EVENTCHANNELSIZE)
	vr.packetQueue = make(chan *VRRPPacket, PACKETQUEUESIZE)
	vr.transitionHandler = make(map[transition]func())

	vr.ipvX = IPvX
	var NetworkInterface, errOfGetIF = net.InterfaceByName(nif)
	if errOfGetIF != nil {
		logger.GLoger.Printf(logger.FATAL, "NewVirtualRouter: %v", errOfGetIF)
	}
	vr.netInterface = NetworkInterface
	//find preferred local IP address
	if preferred, errOfGetPreferred := findIPbyInterface(NetworkInterface, IPvX); errOfGetPreferred != nil {
		logger.GLoger.Printf(logger.FATAL, "NewVirtualRouter: %v", errOfGetPreferred)
	} else {
		vr.preferredSourceIP = preferred
	}
	if IPvX == IPv4 {
		//set up ARP client
		vr.ipAddrAnnouncer = NewIPv4AddrAnnouncer()
	} else {
		//set up ND client
		vr.ipAddrAnnouncer = NewIPIPv6AddrAnnouncer()
	}
	logger.GLoger.Printf(logger.INFO, "virtual router %v initialized, working on %v", VRID, nif)
	return vr

}

func (r *VirtualRouter) setPriority(Priority byte) *VirtualRouter {
	if r.owner {
		return r
	}
	r.priority = Priority
	return r
}

func (r *VirtualRouter) SetAdvInterval(Interval time.Duration) *VirtualRouter {
	if Interval < 10*time.Millisecond {
		panic("interval can not less than 10 ms")
	}
	r.advertisementInterval = uint16(Interval / (10 * time.Millisecond))
	return r
}

func (r *VirtualRouter) SetPriorityAndMasterAdvInterval(priority byte, interval time.Duration) *VirtualRouter {
	r.setPriority(priority)
	if interval < 10*time.Millisecond {
		panic("interval can not less than 10 ms")
	}
	r.setMasterAdvInterval(uint16(interval / (10 * time.Millisecond)))
	return r
}

func (r *VirtualRouter) setMasterAdvInterval(Interval uint16) *VirtualRouter {
	r.advertisementIntervalOfMaster = Interval
	r.skewTime = r.advertisementIntervalOfMaster - uint16(float32(r.advertisementIntervalOfMaster)*float32(r.priority)/256)
	r.masterDownInterval = 3*r.advertisementIntervalOfMaster + r.skewTime
	//从MasterDownInterval和SkewTime的计算方式来看，同一组VirtualRouter中，Priority越高的Router越快地认为某个Master失效
	return r
}

func (r *VirtualRouter) SetPreemptMode(flag bool) *VirtualRouter {
	r.preempt = flag
	return r
}

func (r *VirtualRouter) AddIPvXAddr(iface string, ip net.IP) error {
	var key [16]byte
	copy(key[:], ip.To16())
	networkIface, err := net.InterfaceByName(iface)
	if err != nil {
		logger.GLoger.Printf(logger.ERROR, "VirtualRouter.AddIPvXAddr: interface is not found for IP %v", ip)
		return err
	}
	if _, ok := r.protectedIPaddrs[key]; ok {
		logger.GLoger.Printf(logger.ERROR, "VirtualRouter.AddIPvXAddr: add redundant IP addr %v", ip)
		return nil
	}
	r.protectedIPaddrs[key] = networkIface
	logger.GLoger.Printf(logger.INFO, "VirtualRouter.AddIPvXAddr: IP %v associated with interface %s", ip, networkIface.Name)
	return nil
}

func (r *VirtualRouter) RemoveIPvXAddr(ip net.IP) {
	var key [16]byte
	copy(key[:], ip)
	if _, ok := r.protectedIPaddrs[key]; ok {
		delete(r.protectedIPaddrs, key)
		logger.GLoger.Printf(logger.INFO, "IP %v removed", ip)
	} else {
		logger.GLoger.Printf(logger.ERROR, "VirtualRouter.RemoveIPvXAddr: remove inexistent IP addr %v", ip)
	}
}

func (r *VirtualRouter) sendAdvertMessage() {
	for k := range r.protectedIPaddrs {
		logger.GLoger.Printf(logger.DEBUG, "send advert message of IP %v", net.IP(k[:]))
	}
	var x = r.assembleVRRPPacket()

	// RFC 5798: In unicast mode, send to all configured peer addresses
	if r.unicastMode && len(r.unicastPeers) > 0 {
		for _, peer := range r.unicastPeers {
			if errOfWrite := r.iplayerInterface.WriteMessageTo(x, peer); errOfWrite != nil {
				logger.GLoger.Printf(logger.ERROR, "VirtualRouter.WriteMessageTo: failed to send to peer %v: %v", peer, errOfWrite)
			} else {
				logger.GLoger.Printf(logger.DEBUG, "sent VRRP advertisement to unicast peer %v", peer)
			}
		}
	} else {
		// Multicast mode (default)
		if errOfWrite := r.iplayerInterface.WriteMessage(x); errOfWrite != nil {
			logger.GLoger.Printf(logger.ERROR, "VirtualRouter.WriteMessage: %v", errOfWrite)
		}
	}
}

// assembleVRRPPacket assemble VRRP advert packet
func (r *VirtualRouter) assembleVRRPPacket() *VRRPPacket {

	var packet VRRPPacket
	packet.SetPriority(r.priority)
	packet.SetVersion(VRRPv3)
	packet.SetVirtualRouterID(r.vrID)
	packet.SetAdvertisementInterval(r.advertisementInterval)
	packet.SetType()
	for k := range r.protectedIPaddrs {
		packet.AddIPvXAddr(r.ipvX, net.IP(k[:]))
	}
	var pshdr PseudoHeader
	pshdr.Protocol = VRRPIPProtocolNumber
	// RFC 5798: In unicast mode, use the first peer address for checksum calculation
	// In multicast mode, use the multicast address
	if r.unicastMode && len(r.unicastPeers) > 0 {
		pshdr.Daddr = r.unicastPeers[0]
	} else {
		if r.ipvX == IPv4 {
			pshdr.Daddr = VRRPMultiAddrIPv4
		} else {
			pshdr.Daddr = VRRPMultiAddrIPv6
		}
	}
	pshdr.Len = uint16(len(packet.ToBytes()))
	pshdr.Saddr = r.preferredSourceIP
	packet.SetCheckSum(&pshdr)
	return &packet
}

// fetchVRRPPacket read VRRP packet from IP layer then push into Packet queue
func (r *VirtualRouter) fetchVRRPPacket() {
	for {
		if packet, errofFetch := r.iplayerInterface.ReadMessage(); errofFetch != nil {
			logger.GLoger.Printf(logger.ERROR, "VirtualRouter.fetchVRRPPacket: %v", errofFetch)
		} else {
			// Verify VRID matches
			if r.vrID != packet.GetVirtualRouterID() {
				logger.GLoger.Printf(logger.ERROR, "VirtualRouter.fetchVRRPPacket: received a advertisement with different ID: %v", packet.GetVirtualRouterID())
				continue
			}

			// RFC 5798: In unicast mode, verify that the packet is from a configured peer
			if r.unicastMode && len(r.unicastPeers) > 0 {
				if packet.Pshdr == nil {
					logger.GLoger.Printf(logger.ERROR, "VirtualRouter.fetchVRRPPacket: packet missing pseudo header")
					continue
				}
				senderIP := packet.Pshdr.Saddr
				peerFound := false
				for _, peer := range r.unicastPeers {
					if peer.Equal(senderIP) {
						peerFound = true
						break
					}
				}
				if !peerFound {
					logger.GLoger.Printf(logger.DEBUG, "VirtualRouter.fetchVRRPPacket: received packet from non-peer address %v in unicast mode, ignoring", senderIP)
					continue
				}
			}

			r.packetQueue <- packet
			logger.GLoger.Printf(logger.DEBUG, "VirtualRouter.fetchVRRPPacket: received one advertisement")
		}
	}
}

func (r *VirtualRouter) makeAdvertTicker() {
	r.advertisementTicker = time.NewTicker(time.Duration(r.advertisementInterval*10) * time.Millisecond)
}

func (r *VirtualRouter) stopAdvertTicker() {
	r.advertisementTicker.Stop()
}

func (r *VirtualRouter) makeMasterDownTimer() {
	if r.masterDownTimer == nil {
		r.masterDownTimer = time.NewTimer(time.Duration(r.masterDownInterval*10) * time.Millisecond)
	} else {
		r.resetMasterDownTimer()
	}
}

func (r *VirtualRouter) stopMasterDownTimer() {
	logger.GLoger.Printf(logger.DEBUG, "master down timer stopped")
	if !r.masterDownTimer.Stop() {
		select {
		case <-r.masterDownTimer.C:
		default:
		}
		logger.GLoger.Printf(logger.DEBUG, "master down timer expired before we stop it, drain the channel")
	}
}

func (r *VirtualRouter) resetMasterDownTimer() {
	r.stopMasterDownTimer()
	r.masterDownTimer.Reset(time.Duration(r.masterDownInterval*10) * time.Millisecond)
}

func (r *VirtualRouter) resetMasterDownTimerToSkewTime() {
	r.stopMasterDownTimer()
	r.masterDownTimer.Reset(time.Duration(r.skewTime*10) * time.Millisecond)
}

func (r *VirtualRouter) Enroll(transition2 transition, handler func()) bool {
	if _, ok := r.transitionHandler[transition2]; ok {
		logger.GLoger.Printf(logger.INFO, fmt.Sprintf("VirtualRouter.Enroll(): handler of transition [%s] overwrited", transition2))
		r.transitionHandler[transition2] = handler
		return true
	}
	logger.GLoger.Printf(logger.INFO, fmt.Sprintf("VirtualRouter.Enroll(): handler of transition [%s] enrolled", transition2))
	r.transitionHandler[transition2] = handler
	return false
}

func (r *VirtualRouter) transitionDoWork(t transition) {
	var work, ok = r.transitionHandler[t]
	if ok == false {
		//return fmt.Errorf("VirtualRouter.transitionDoWork(): handler of [%s] does not exist", t)
		return
	}
	work()
	logger.GLoger.Printf(logger.INFO, fmt.Sprintf("handler of transition [%s] called", t))
	return
}

// ///////////////////////////////////////
func largerThan(ip1, ip2 net.IP) bool {
	if len(ip1) != len(ip2) {
		logger.GLoger.Printf(logger.FATAL, "largerThan: two compared IP addresses must have the same length")
	}
	for index := range ip1 {
		if ip1[index] > ip2[index] {
			return true
		} else if ip1[index] < ip2[index] {
			return false
		}
	}
	return false
}

// eventLoop VRRP event loop to handle various triggered events
func (r *VirtualRouter) eventLoop() {
	for {
		switch r.state {
		case INIT:
			select {
			case event := <-r.eventChannel:
				if event == START {
					logger.GLoger.Printf(logger.INFO, "event %v received", event)
					if r.priority == 255 || r.owner {
						logger.GLoger.Printf(logger.INFO, "enter owner mode")
						r.sendAdvertMessage()
						if errOfarp := r.ipAddrAnnouncer.AnnounceAll(r); errOfarp != nil {
							logger.GLoger.Printf(logger.ERROR, "VirtualRouter.EventLoop: %v", errOfarp)
						}
						//set up advertisement timer
						r.makeAdvertTicker()
						logger.GLoger.Printf(logger.DEBUG, "enter MASTER state")
						r.state = MASTER
						r.transitionDoWork(Init2Master)
					} else {
						logger.GLoger.Printf(logger.INFO, "VR is not the owner of protected IP addresses")
						r.setMasterAdvInterval(r.advertisementInterval)
						//set up master down timer
						r.makeMasterDownTimer()
						logger.GLoger.Printf(logger.DEBUG, "enter BACKUP state")
						r.state = BACKUP
						r.transitionDoWork(Init2Backup)
					}
				}
			}
		case MASTER:
			//check if shutdown event received
			select {
			case event := <-r.eventChannel:
				if event == SHUTDOWN {
					//close advert timer
					r.stopAdvertTicker()
					//send advertisement with priority 0
					var priority = r.priority
					r.setPriority(0)
					r.sendAdvertMessage()
					r.setPriority(priority)
					//transition into INIT
					r.state = INIT
					r.transitionDoWork(Master2Init)
					logger.GLoger.Printf(logger.INFO, "event %v received", event)
					//maybe we can break out the event loop
				}
			case <-r.advertisementTicker.C: //check if advertisement timer fired
				r.sendAdvertMessage()
			default:
				//nothing to do, just break
			}
			//process incoming advertisement
			select {
			case packet := <-r.packetQueue:
				if packet.GetPriority() == 0 {
					//I don't think we should anything here
				} else {
					if packet.GetPriority() > r.priority || (packet.GetPriority() == r.priority && largerThan(packet.Pshdr.Saddr, r.preferredSourceIP)) {

						//cancel Advertisement timer
						r.stopAdvertTicker()
						//set up master down timer
						r.setMasterAdvInterval(packet.GetAdvertisementInterval())
						r.makeMasterDownTimer()
						r.state = BACKUP
						r.transitionDoWork(Master2Backup)
					} else {
						//just discard this one
					}
				}
			default:
				//nothing to do
			}
		case BACKUP:
			select {
			case event := <-r.eventChannel:
				if event == SHUTDOWN {
					//close master down timer
					r.stopMasterDownTimer()
					//transition into INIT
					r.state = INIT
					r.transitionDoWork(Backup2Init)
					logger.GLoger.Printf(logger.INFO, "event %s received", event)
				}
			default:
			}
			//process incoming advertisement
			select {
			case packet := <-r.packetQueue:
				if packet.GetPriority() == 0 {
					logger.GLoger.Printf(logger.INFO, "received an advertisement with priority 0, transit into MASTER state (VRID %v)", r.vrID)
					//Set the Master_Down_Timer to Skew_Time
					r.resetMasterDownTimerToSkewTime()
				} else {
					if r.preempt == false || packet.GetPriority() > r.priority || (packet.GetPriority() == r.priority && largerThan(packet.Pshdr.Saddr, r.preferredSourceIP)) {
						//reset master down timer
						r.setMasterAdvInterval(packet.GetAdvertisementInterval())
						r.resetMasterDownTimer()
					} else {
						//nothing to do, just discard this one
					}
				}
			default:
				//nothing to do
			}
			select {
			//Master_Down_Timer fired
			case <-r.masterDownTimer.C:
				// Send an ADVERTISEMENT
				r.sendAdvertMessage()
				if errOfARP := r.ipAddrAnnouncer.AnnounceAll(r); errOfARP != nil {
					logger.GLoger.Printf(logger.ERROR, "VirtualRouter.EventLoop: %v", errOfARP)
				}
				//Set the Advertisement Timer to Advertisement interval
				r.makeAdvertTicker()

				r.state = MASTER
				r.transitionDoWork(Backup2Master)
			default:
				//nothing to do
			}

		}
	}
}

// eventSelector VRRP event selector to handle various triggered events
func (r *VirtualRouter) eventSelector() {
	for {
		switch r.state {
		case INIT:
			select {
			case event := <-r.eventChannel:
				if event == START {
					logger.GLoger.Printf(logger.INFO, "event %v received", event)
					if r.priority == 255 || r.owner {
						logger.GLoger.Printf(logger.INFO, "enter owner mode")
						r.sendAdvertMessage()
						if errOfarp := r.ipAddrAnnouncer.AnnounceAll(r); errOfarp != nil {
							logger.GLoger.Printf(logger.ERROR, "VirtualRouter.EventLoop: %v", errOfarp)
						}
						//set up advertisement timer
						r.makeAdvertTicker()

						logger.GLoger.Printf(logger.DEBUG, "enter MASTER state")
						r.state = MASTER
						r.transitionDoWork(Init2Master)
					} else {
						logger.GLoger.Printf(logger.INFO, "VR is not the owner of protected IP addresses")
						r.setMasterAdvInterval(r.advertisementInterval)
						//set up master down timer
						r.makeMasterDownTimer()
						logger.GLoger.Printf(logger.DEBUG, "enter BACKUP state")
						r.state = BACKUP
						r.transitionDoWork(Init2Backup)
					}
				}
			}
		case MASTER:
			//check if shutdown event received
			select {
			case event := <-r.eventChannel:
				if event == SHUTDOWN {
					//close advert timer
					r.stopAdvertTicker()
					//send advertisement with priority 0
					var priority = r.priority
					r.setPriority(0)
					r.sendAdvertMessage()
					r.setPriority(priority)
					//transition into INIT
					r.state = INIT
					r.transitionDoWork(Master2Init)
					logger.GLoger.Printf(logger.INFO, "event %v received", event)
					//maybe we can break out the event loop
				}
			case <-r.advertisementTicker.C: //check if advertisement timer fired
				r.sendAdvertMessage()
			case packet := <-r.packetQueue: //process incoming advertisement
				if packet.GetPriority() == 0 {
					//I don't think we should anything here
				} else {
					if packet.GetPriority() > r.priority || (packet.GetPriority() == r.priority && largerThan(packet.Pshdr.Saddr, r.preferredSourceIP)) {

						//cancel Advertisement timer
						r.stopAdvertTicker()
						//set up master down timer
						r.setMasterAdvInterval(packet.GetAdvertisementInterval())
						r.makeMasterDownTimer()
						r.state = BACKUP
						r.transitionDoWork(Master2Backup)
					} else {
						//just discard this one
					}
				}
			}

		case BACKUP:
			select {
			case event := <-r.eventChannel:
				if event == SHUTDOWN {
					//close master down timer
					r.stopMasterDownTimer()
					//transition into INIT
					r.state = INIT
					r.transitionDoWork(Backup2Init)
					logger.GLoger.Printf(logger.INFO, "event %s received", event)
				}
			case packet := <-r.packetQueue: //process incoming advertisement
				if packet.GetPriority() == 0 {
					logger.GLoger.Printf(logger.INFO, "received an advertisement with priority 0, transit into MASTER state (VRID %v)", r.vrID)
					//Set the Master_Down_Timer to Skew_Time
					r.resetMasterDownTimerToSkewTime()
				} else {
					if r.preempt == false || packet.GetPriority() > r.priority || (packet.GetPriority() == r.priority && largerThan(packet.Pshdr.Saddr, r.preferredSourceIP)) {
						//reset master down timer
						r.setMasterAdvInterval(packet.GetAdvertisementInterval())
						r.resetMasterDownTimer()
					} else {
						//nothing to do, just discard this one
					}
				}
			case <-r.masterDownTimer.C: //Master_Down_Timer fired
				// Send an ADVERTISEMENT
				r.sendAdvertMessage()
				if errOfARP := r.ipAddrAnnouncer.AnnounceAll(r); errOfARP != nil {
					logger.GLoger.Printf(logger.ERROR, "VirtualRouter.EventLoop: %v", errOfARP)
				}
				//Set the Advertisement Timer to Advertisement interval
				r.makeAdvertTicker()
				r.state = MASTER
				r.transitionDoWork(Backup2Master)
			}

		}
	}
}

func (vr *VirtualRouter) StartWithEventLoop() {
	go vr.fetchVRRPPacket()
	go func() {
		vr.eventChannel <- START
	}()

	vr.eventLoop()
}

func (vr *VirtualRouter) StartWithEventSelector() {
	go vr.fetchVRRPPacket()
	go func() {
		vr.eventChannel <- START
	}()

	vr.eventSelector()
}

func (vr *VirtualRouter) Stop() {
	vr.eventChannel <- SHUTDOWN
}

// SetUnicastMode enables or disables unicast mode (RFC 5798)
// When enabled, VRRP advertisements will be sent to configured unicast peer addresses
// instead of the multicast address.SetUnicastMode must be called before StartWithEventSelector or StartWithEventLoop
func (vr *VirtualRouter) SetUnicastMode(enabled bool) *VirtualRouter {
	vr.unicastMode = enabled
	if enabled {
		logger.GLoger.Printf(logger.INFO, "unicast mode enabled for virtual router %v", vr.vrID)
	} else {
		logger.GLoger.Printf(logger.INFO, "unicast mode disabled (multicast mode) for virtual router %v", vr.vrID)
	}
	if vr.ipvX == IPv4 {
		//set up IPv4 interface
		if vr.unicastMode {
			vr.iplayerInterface = NewIPv4ConnUnicast(vr.preferredSourceIP, vr.unicastPeers[0])
		} else {
			vr.iplayerInterface = NewIPv4ConnMulticast(vr.preferredSourceIP, VRRPMultiAddrIPv4)
		}
	} else {
		//set up IPv6 interface
		if vr.unicastMode {
			vr.iplayerInterface = NewIPv6ConUnicast(vr.preferredSourceIP, vr.unicastPeers[0])
		} else {
			vr.iplayerInterface = NewIPv6ConMulticast(vr.preferredSourceIP, VRRPMultiAddrIPv6)
		}
	}
	return vr
}

// IsUnicastMode returns whether unicast mode is enabled
func (vr *VirtualRouter) IsUnicastMode() bool {
	return vr.unicastMode
}

// AddUnicastPeer adds a unicast peer address for RFC 5798 unicast mode
// In unicast mode, VRRP advertisements will be sent to all configured peer addresses
// AddUnicastPeer must be called before SetUnicastMode
func (vr *VirtualRouter) AddUnicastPeer(peer net.IP) *VirtualRouter {
	// Validate that peer address matches the IP version
	if vr.ipvX == IPv4 && peer.To4() == nil {
		logger.GLoger.Printf(logger.ERROR, "AddUnicastPeer: IPv4 virtual router cannot have IPv6 peer %v", peer)
		return vr
	}
	if vr.ipvX == IPv6 && peer.To4() != nil {
		logger.GLoger.Printf(logger.ERROR, "AddUnicastPeer: IPv6 virtual router cannot have IPv4 peer %v", peer)
		return vr
	}

	// Check if peer already exists
	for _, existingPeer := range vr.unicastPeers {
		if existingPeer.Equal(peer) {
			logger.GLoger.Printf(logger.DEBUG, "AddUnicastPeer: peer %v already exists", peer)
			return vr
		}
	}

	vr.unicastPeers = append(vr.unicastPeers, peer)
	logger.GLoger.Printf(logger.INFO, "unicast peer %v added to virtual router %v", peer, vr.vrID)
	return vr
}

// RemoveUnicastPeer removes a unicast peer address
func (vr *VirtualRouter) RemoveUnicastPeer(peer net.IP) *VirtualRouter {
	for i, existingPeer := range vr.unicastPeers {
		if existingPeer.Equal(peer) {
			vr.unicastPeers = append(vr.unicastPeers[:i], vr.unicastPeers[i+1:]...)
			logger.GLoger.Printf(logger.INFO, "unicast peer %v removed from virtual router %v", peer, vr.vrID)
			return vr
		}
	}
	logger.GLoger.Printf(logger.ERROR, "RemoveUnicastPeer: peer %v not found", peer)
	return vr
}

// ClearUnicastPeers removes all unicast peer addresses
func (vr *VirtualRouter) ClearUnicastPeers() *VirtualRouter {
	vr.unicastPeers = make([]net.IP, 0)
	logger.GLoger.Printf(logger.INFO, "all unicast peers cleared for virtual router %v", vr.vrID)
	return vr
}

// GetUnicastPeers returns a copy of the unicast peer addresses list
func (vr *VirtualRouter) GetUnicastPeers() []net.IP {
	peers := make([]net.IP, len(vr.unicastPeers))
	copy(peers, vr.unicastPeers)
	return peers
}
