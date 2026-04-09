package vrrp

import (
	"fmt"
	"net"
	"sync"
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
	preemptDelay                  time.Duration
	preemptDelayTimer             *time.Timer
	preemptPending                bool
	owner                         bool
	useVMAC                       bool
	virtualRouterMACAddressIPv4   net.HardwareAddr
	virtualRouterMACAddressIPv6   net.HardwareAddr
	//
	unicastMode  bool
	unicastPeers []net.IP // Unicast peer addresses for RFC 5798 unicast mode
	//
	interfaceByName        func(string) (*net.Interface, error)
	heartbeatInterface     string
	heartbeatDownMaster    bool
	faultOwnsVIPs          bool
	heartbeatSubscribe     func(string, byte, chan<- heartbeatLinkUpdate, <-chan struct{}) error
	heartbeatMu            sync.RWMutex
	heartbeatUp            bool
	heartbeatKnown         bool
	ipvX                   byte
	preferredSourceIP      net.IP
	protectedIPaddrs       map[[16]byte]*net.Interface
	managedVIPs            map[[16]byte]*managedVIP
	managedVMACs           map[string]string
	state                  int
	iplayerInterface       IPConnection
	ipAddrAnnouncer        AddrAnnouncer
	netlinkOps             netlinkOps
	garpMasterRepeat       int
	garpMasterDelay        int
	garpMasterSendInterval int
	garpThrottleInterval   time.Duration
	garpOperation          GratuitousARPOperation
	eventChannel           chan EVENT
	packetQueue            chan *VRRPPacket
	advertisementTicker    *time.Ticker
	masterDownTimer        *time.Timer
	gratuitousArpTimer     *time.Timer
	transitionHandler      map[transition]func(int)
	stopSignal             chan struct{}
	shutdownOnce           sync.Once
	stopRequestOnce        sync.Once
}

// NewVirtualRouter create a new virtual router with designated parameters
func NewVirtualRouter(VRID byte, nif string, Owner bool, IPvX byte) (*VirtualRouter, error) {
	if VRID == 0 {
		return nil, fmt.Errorf("NewVirtualRouter: VRID must be in range 1-255")
	}
	if IPvX != IPv4 && IPvX != IPv6 {
		return nil, fmt.Errorf("NewVirtualRouter: parameter IPvx must be IPv4 or IPv6")
	}
	var vr = &VirtualRouter{}
	vr.interfaceByName = net.InterfaceByName
	vr.ipvX = IPvX
	var NetworkInterface, errOfGetIF = vr.lookupInterface(nif)
	if errOfGetIF != nil {
		return nil, fmt.Errorf("NewVirtualRouter: %v", errOfGetIF)
	}
	vr.heartbeatInterface = nif
	vr.setHeartbeatStatus(vr.checkHeartbeatInterface())
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
	vr.garpMasterRepeat = 5
	vr.garpMasterDelay = 3 //12
	vr.garpMasterSendInterval = defaultGARPSendInterval
	vr.garpThrottleInterval = defaultGARPThrottleInterval
	//make
	vr.protectedIPaddrs = make(map[[16]byte]*net.Interface)
	vr.managedVIPs = make(map[[16]byte]*managedVIP)
	vr.managedVMACs = make(map[string]string)
	vr.unicastPeers = make([]net.IP, 0)
	vr.eventChannel = make(chan EVENT, EVENTCHANNELSIZE)
	vr.packetQueue = make(chan *VRRPPacket, PACKETQUEUESIZE)
	vr.transitionHandler = make(map[transition]func(int))
	vr.netlinkOps = systemNetlinkOps{}
	vr.stopSignal = make(chan struct{})
	vr.heartbeatSubscribe = defaultHeartbeatSubscribe

	//find preferred local IP address
	if preferred, err := findIPbyInterface(NetworkInterface, IPvX); err != nil {
		logger.GLoger.Printf(logger.ERROR, "NewVirtualRouter: %v", err)
		return nil, err
	} else {
		vr.preferredSourceIP = preferred
	}
	if IPvX == IPv4 {
		//set up ARP client
		vr.ipAddrAnnouncer = NewIPv4AddrAnnouncer()
		if vr.preferredSourceIP != nil {
			var err error
			vr.iplayerInterface, err = NewIPv4ConnMulticast(vr.preferredSourceIP, VRRPMultiAddrIPv4)
			if err != nil {
				return nil, fmt.Errorf("NewVirtualRouter: %v", err)
			}
		}
	} else {
		//set up ND client
		vr.ipAddrAnnouncer = NewIPIPv6AddrAnnouncer()
		if vr.preferredSourceIP != nil {
			var err error
			vr.iplayerInterface, err = NewIPv6ConMulticast(vr.preferredSourceIP, VRRPMultiAddrIPv6)
			if err != nil {
				return nil, fmt.Errorf("NewVirtualRouter: %v", err)
			}
		}
	}
	logger.GLoger.Printf(logger.INFO, "virtual router %v initialized, working on %v", VRID, nif)
	return vr, nil

}

func (r *VirtualRouter) SetPriority(Priority byte) *VirtualRouter {
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
	r.SetPriority(priority)
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

func (r *VirtualRouter) SetPreemptDelay(delay time.Duration) *VirtualRouter {
	if delay < 0 {
		panic("preempt delay can not be negative")
	}
	r.preemptDelay = delay
	return r
}

func (r *VirtualRouter) SetGratuitousARPOperation(operation GratuitousARPOperation) *VirtualRouter {
	switch operation {
	case GratuitousARPRequest, GratuitousARPReply:
		r.garpOperation = operation
	default:
		logger.GLoger.Printf(logger.ERROR, "SetGratuitousARPOperation: unsupported gratuitous ARP operation %d", operation)
	}
	return r
}

func (r *VirtualRouter) SetGratuitousARPThrottleInterval(interval time.Duration) *VirtualRouter {
	if interval < 0 {
		logger.GLoger.Printf(logger.ERROR, "SetGratuitousARPThrottleInterval: interval must be non-negative")
		return r
	}
	r.garpThrottleInterval = interval
	return r
}

func (r *VirtualRouter) SetHeartbeatDownMaster(flag bool) *VirtualRouter {
	r.heartbeatDownMaster = flag
	return r
}

func (r *VirtualRouter) AddIPvXAddr(iface string, ip net.IP) error {
	var key [16]byte
	copy(key[:], ip.To16())
	networkIface, err := r.lookupInterface(iface)
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

func (r *VirtualRouter) lookupInterface(name string) (*net.Interface, error) {
	if r.interfaceByName != nil {
		return r.interfaceByName(name)
	}
	return net.InterfaceByName(name)
}

func (r *VirtualRouter) setHeartbeatStatus(up bool) {
	r.heartbeatMu.Lock()
	r.heartbeatUp = up
	r.heartbeatKnown = true
	r.heartbeatMu.Unlock()
}

func (r *VirtualRouter) heartbeatStatus() (bool, bool) {
	r.heartbeatMu.RLock()
	defer r.heartbeatMu.RUnlock()
	return r.heartbeatUp, r.heartbeatKnown
}

func (r *VirtualRouter) isHeartbeatUp() bool {
	if up, known := r.heartbeatStatus(); known {
		return up
	}
	return r.checkHeartbeatInterface()
}

func (r *VirtualRouter) checkHeartbeatInterface() bool {
	ifc, err := r.lookupInterface(r.heartbeatInterface)
	if err != nil {
		return false
	}
	if ifc.Flags&net.FlagRunning == 0 {
		return false
	}
	addrs, err := ifc.Addrs()
	if err != nil {
		return false
	}
	return heartbeatHasGlobalUnicastAddressForVersion(addrs, r.ipvX)
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
	if r.state == FAULT {
		return
	}
	// for k := range r.protectedIPaddrs {
	// 	logger.GLoger.Printf(logger.DEBUG, "send advert message of IP %v", net.IP(k[:]))
	// }

	// RFC 5798: In unicast mode, send to all configured peer addresses
	if r.unicastMode && len(r.unicastPeers) > 0 {
		for _, peer := range r.unicastPeers {
			packet := r.assembleVRRPPacketForDestination(peer)
			if errOfWrite := r.iplayerInterface.WriteMessageTo(packet, peer); errOfWrite != nil {
				logger.GLoger.Printf(logger.ERROR, "VirtualRouter.WriteMessageTo: failed to send to peer %v: %v", peer, errOfWrite)
			} else {
				logger.GLoger.Printf(logger.DEBUG, "sent VRRP advertisement to unicast peer %v", peer)
			}
		}
	} else {
		packet := r.assembleVRRPPacket()
		// Multicast mode (default)
		if errOfWrite := r.iplayerInterface.WriteMessage(packet); errOfWrite != nil {
			logger.GLoger.Printf(logger.ERROR, "VirtualRouter.WriteMessage: %v", errOfWrite)
		}
	}
}

// assembleVRRPPacket assemble VRRP advert packet
func (r *VirtualRouter) assembleVRRPPacket() *VRRPPacket {
	var dest net.IP
	if r.ipvX == IPv4 {
		dest = VRRPMultiAddrIPv4
	} else {
		dest = VRRPMultiAddrIPv6
	}
	return r.assembleVRRPPacketForDestination(dest)
}

func (r *VirtualRouter) assembleVRRPPacketForDestination(dest net.IP) *VRRPPacket {
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
	pshdr.Daddr = dest
	pshdr.Len = uint16(len(packet.ToBytes()))
	pshdr.Saddr = r.preferredSourceIP
	packet.SetCheckSum(&pshdr)
	return &packet
}

// fetchVRRPPacket read VRRP packet from IP layer then push into Packet queue
func (r *VirtualRouter) fetchVRRPPacket() {
	for {
		if packet, errofFetch := r.iplayerInterface.ReadMessage(); errofFetch != nil {
			if r.isStopping() {
				return
			}
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

			select {
			case r.packetQueue <- packet:
			case <-r.stopSignal:
				return
			}
			//logger.GLoger.Printf(logger.DEBUG, "VirtualRouter.fetchVRRPPacket: received one advertisement")
		}
	}
}

func (r *VirtualRouter) makeAdvertTicker() {
	r.advertisementTicker = time.NewTicker(time.Duration(r.advertisementInterval*10) * time.Millisecond)
}

func (r *VirtualRouter) stopAdvertTicker() {
	if r.advertisementTicker == nil {
		return
	}
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
	if r.masterDownTimer == nil {
		return
	}
	logger.GLoger.Printf(logger.DEBUG, "master down timer stopped")
	// IMPORTANT: Stop() must be paired with selective drain of C to prevent
	// channel leakage or stale firing if the timer already expired.
	if !r.masterDownTimer.Stop() {
		select {
		case <-r.masterDownTimer.C:
		default:
		}
		logger.GLoger.Printf(logger.DEBUG, "master down timer expired before we stop it, drain the channel")
	}
}

func (r *VirtualRouter) resetMasterDownTimer() {
	if r.masterDownTimer == nil {
		r.makeMasterDownTimer()
		return
	}
	r.stopMasterDownTimer()
	r.masterDownTimer.Reset(time.Duration(r.masterDownInterval*10) * time.Millisecond)
}

func (r *VirtualRouter) resetMasterDownTimerToSkewTime() {
	if r.masterDownTimer == nil {
		r.masterDownTimer = time.NewTimer(time.Duration(r.skewTime*10) * time.Millisecond)
		return
	}
	r.stopMasterDownTimer()
	r.masterDownTimer.Reset(time.Duration(r.skewTime*10) * time.Millisecond)
}

func (r *VirtualRouter) makePreemptDelayTimer() {
	if r.preemptDelay <= 0 {
		return
	}
	if r.preemptDelayTimer == nil {
		r.preemptDelayTimer = time.NewTimer(r.preemptDelay)
		return
	}
	if !r.preemptDelayTimer.Stop() {
		select {
		case <-r.preemptDelayTimer.C:
		default:
		}
	}
	r.preemptDelayTimer.Reset(r.preemptDelay)
}

func (r *VirtualRouter) stopPreemptDelayTimer() {
	if r.preemptDelayTimer == nil {
		r.preemptPending = false
		return
	}
	if !r.preemptDelayTimer.Stop() {
		select {
		case <-r.preemptDelayTimer.C:
		default:
		}
	}
	r.preemptDelayTimer = nil
	r.preemptPending = false
}

func (r *VirtualRouter) clearPreemptDelay() {
	r.stopPreemptDelayTimer()
}

func (r *VirtualRouter) handleBackupPacket(packet *VRRPPacket) bool {
	if packet.GetPriority() == 0 {
		logger.GLoger.Printf(logger.INFO, "received an advertisement with priority 0, transit into MASTER state (VRID %v)", r.vrID)
		r.clearPreemptDelay()
		//Set the Master_Down_Timer to Skew_Time
		r.resetMasterDownTimerToSkewTime()
		return true
	}
	if r.preempt && r.preemptDelay > 0 && (packet.GetPriority() < r.priority || (packet.GetPriority() == r.priority && !largerThan(packet.Pshdr.Saddr, r.preferredSourceIP))) {
		r.setMasterAdvInterval(packet.GetAdvertisementInterval())
		r.resetMasterDownTimer()
		if !r.preemptPending {
			r.preemptPending = true
			r.makePreemptDelayTimer()
		}
		return false
	}
	if r.preempt == false || packet.GetPriority() > r.priority || (packet.GetPriority() == r.priority && largerThan(packet.Pshdr.Saddr, r.preferredSourceIP)) {
		r.clearPreemptDelay()
		//reset master down timer
		r.setMasterAdvInterval(packet.GetAdvertisementInterval())
		r.resetMasterDownTimer()
		return true
	}
	return false
}

func (r *VirtualRouter) drainBackupPackets(blockOnAny bool) bool {
	sawPacket := false
	blocked := false
	for {
		select {
		case packet := <-r.packetQueue:
			sawPacket = true
			if blockOnAny || r.handleBackupPacket(packet) {
				blocked = true
			}
		default:
			return sawPacket && blocked
		}
	}
}

func (r *VirtualRouter) makeGarpTimer(dur int) {
	if r.gratuitousArpTimer == nil {
		r.gratuitousArpTimer = time.NewTimer(time.Duration(dur) * time.Second)
	} else {
		r.resetGarpTimer(dur)
	}
}

func (r *VirtualRouter) resetGarpTimer(dur int) {
	r.stopGarpTimer()
	r.gratuitousArpTimer.Reset(time.Duration(dur) * time.Second)
}

func (r *VirtualRouter) stopGarpTimer() {
	if r.gratuitousArpTimer == nil {
		return
	}
	if !r.gratuitousArpTimer.Stop() {
		select {
		case <-r.gratuitousArpTimer.C:
		default:
		}
	}
}

func (r *VirtualRouter) Enroll(transition2 transition, handler func(int)) bool {
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
	work(r.state)
	logger.GLoger.Printf(logger.INFO, fmt.Sprintf("handler of transition [%s] called", t))
}

func (r *VirtualRouter) closeAnnouncer() {
	if r.ipAddrAnnouncer == nil {
		return
	}
	if err := r.ipAddrAnnouncer.Close(); err != nil {
		logger.GLoger.Printf(logger.ERROR, "VirtualRouter.closeAnnouncer: %v", err)
	}
}

func (r *VirtualRouter) closeIPConnection() {
	if r.iplayerInterface == nil {
		return
	}
	if err := r.iplayerInterface.Close(); err != nil {
		logger.GLoger.Printf(logger.ERROR, "VirtualRouter.closeIPConnection: %v", err)
	}
}

func (r *VirtualRouter) isStopping() bool {
	select {
	case <-r.stopSignal:
		return true
	default:
		return false
	}
}

func (r *VirtualRouter) sendEvent(event EVENT) {
	select {
	case r.eventChannel <- event:
	default:
		go func() {
			select {
			case r.eventChannel <- event:
			case <-r.stopSignal:
			}
		}()
	}
}

func (r *VirtualRouter) monitorHeartbeat() {
	updates := make(chan heartbeatLinkUpdate, 8)
	if err := r.heartbeatSubscribe(r.heartbeatInterface, r.ipvX, updates, r.stopSignal); err != nil {
		logger.GLoger.Printf(logger.ERROR, "VirtualRouter.monitorHeartbeat: %v", err)
		return
	}
	r.setHeartbeatStatus(r.checkHeartbeatInterface())

	for {
		select {
		case update := <-updates:
			if update.Name != r.heartbeatInterface {
				continue
			}
			prev, _ := r.heartbeatStatus()
			r.setHeartbeatStatus(update.Up)
			if update.Up != prev {
				if update.Up {
					r.sendEvent(HEARTBEAT_UP)
				} else {
					r.sendEvent(HEARTBEAT_DOWN)
				}
			}
		case <-r.stopSignal:
			return
		}
	}
}

func (r *VirtualRouter) stopStateTimers() {
	if r.advertisementTicker != nil {
		r.stopAdvertTicker()
	}
	if r.masterDownTimer != nil {
		r.stopMasterDownTimer()
	}
	if r.preemptDelayTimer != nil || r.preemptPending {
		r.clearPreemptDelay()
	}
	if r.gratuitousArpTimer != nil {
		r.stopGarpTimer()
	}
}

func (r *VirtualRouter) enterMaster(trans transition) {
	r.clearPreemptDelay()
	if r.state != MASTER {
		if err := r.activateManagedVIPs(); err != nil {
			logger.GLoger.Printf(logger.ERROR, "VirtualRouter.activateManagedVIPs: %v", err)
		}
	}
	r.state = MASTER
	r.sendAdvertMessage()
	if errOfarp := r.ipAddrAnnouncer.AnnounceAll(r); errOfarp != nil {
		logger.GLoger.Printf(logger.ERROR, "VirtualRouter.EventLoop: %v", errOfarp)
	}
	if r.advertisementTicker == nil {
		r.makeAdvertTicker()
	} else {
		r.stopAdvertTicker()
		r.makeAdvertTicker()
	}
	if trans >= 0 {
		r.transitionDoWork(trans)
	}
	r.makeGarpTimer(r.garpMasterDelay)
}

func (r *VirtualRouter) enterBackup(trans transition, startTimer bool) {
	if err := r.deactivateManagedVIPs(); err != nil {
		logger.GLoger.Printf(logger.ERROR, "VirtualRouter.deactivateManagedVIPs: %v", err)
	}
	r.stopStateTimers()
	r.setMasterAdvInterval(r.advertisementInterval)
	if startTimer {
		r.makeMasterDownTimer()
	}
	r.state = BACKUP
	if trans >= 0 {
		r.transitionDoWork(trans)
	}
}

func (r *VirtualRouter) enterFault(trans transition) {
	r.stopStateTimers()
	if r.heartbeatDownMaster {
		r.faultOwnsVIPs = true
		if trans != Master2Fault {
			if err := r.activateManagedVIPs(); err != nil {
				logger.GLoger.Printf(logger.ERROR, "VirtualRouter.activateManagedVIPs: %v", err)
			}
			if err := r.ipAddrAnnouncer.AnnounceAll(r); err != nil {
				logger.GLoger.Printf(logger.ERROR, "VirtualRouter.enterFault: %v", err)
			}
		}
	} else {
		r.faultOwnsVIPs = false
		if err := r.deactivateManagedVIPs(); err != nil {
			logger.GLoger.Printf(logger.ERROR, "VirtualRouter.deactivateManagedVIPs: %v", err)
		}
	}
	r.state = FAULT
	if trans >= 0 {
		r.transitionDoWork(trans)
	}
}

func (r *VirtualRouter) shutdownResources() {
	r.shutdownOnce.Do(func() {
		close(r.stopSignal)
		r.stopStateTimers()
		if err := r.deactivateManagedVIPs(); err != nil {
			logger.GLoger.Printf(logger.ERROR, "VirtualRouter.shutdownResources deactivate VIPs: %v", err)
		}
		r.closeAnnouncer()
		r.closeIPConnection()
		if err := r.destroyManagedVMACs(); err != nil {
			logger.GLoger.Printf(logger.ERROR, "VirtualRouter.shutdownResources destroy VMACs: %v", err)
		}
	})
}

// ///////////////////////////////////////
func largerThan(ip1, ip2 net.IP) bool {
	if len(ip1) != len(ip2) {
		logger.GLoger.Printf(logger.ERROR, "largerThan: two compared IP addresses must have the same length")
		return false
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

func (r *VirtualRouter) shutdownAll(trans transition) {
	if err := r.deactivateManagedVIPs(); err != nil {
		logger.GLoger.Printf(logger.ERROR, "VirtualRouter.deactivateManagedVIPs: %v", err)
	}
	r.shutdownResources()
	r.state = INIT
	if trans >= 0 {
		r.transitionDoWork(trans)
	}
}

// eventSelector VRRP event selector to handle various triggered events
func (r *VirtualRouter) eventSelector() {
	for {
		switch r.state {
		case INIT:
			select {
			case event := <-r.eventChannel:
				switch event {
				case SHUTDOWN:
					r.shutdownResources()
					return
				case HEARTBEAT_DOWN:
					logger.GLoger.Printf(logger.INFO, "heartbeat interface %s down", r.heartbeatInterface)
					r.enterFault(Init2Fault)
				case START:
					logger.GLoger.Printf(logger.INFO, "event %v received", event)
					if !r.isHeartbeatUp() {
						r.enterFault(Init2Fault)
						continue
					}
					if r.priority == 255 || r.owner {
						logger.GLoger.Printf(logger.INFO, "enter owner mode")
						r.enterMaster(Init2Master)
						continue
					}
					logger.GLoger.Printf(logger.INFO, "VR is not the owner of protected IP addresses")
					r.enterBackup(Init2Backup, true)
				}
			}
		case MASTER:
			//check if shutdown event received
			select {
			case event := <-r.eventChannel:
				if event == SHUTDOWN {
					//send advertisement with priority 0
					priority := r.priority
					r.SetPriority(0)
					r.sendAdvertMessage()
					r.SetPriority(priority)

					r.shutdownAll(Master2Init)
					logger.GLoger.Printf(logger.INFO, "event %v received", event)
					return
				}
				if event == HEARTBEAT_DOWN {
					logger.GLoger.Printf(logger.INFO, "heartbeat interface %s down", r.heartbeatInterface)
					r.enterFault(Master2Fault)
				}
			case <-r.advertisementTicker.C: //check if advertisement timer fired
				r.sendAdvertMessage()
			case <-r.gratuitousArpTimer.C:
				if err := r.ipAddrAnnouncer.AnnounceAll(r); err != nil {
					logger.GLoger.Printf(logger.ERROR, "VirtualRouter.EventLoop: %v", err)
				}
				r.resetGarpTimer(r.garpMasterSendInterval)
			case packet := <-r.packetQueue: //process incoming advertisement
				if packet.GetPriority() > r.priority || (packet.GetPriority() == r.priority && largerThan(packet.Pshdr.Saddr, r.preferredSourceIP)) {
					//cancel Advertisement timer
					r.stopAdvertTicker()
					//set up master down timer
					r.setMasterAdvInterval(packet.GetAdvertisementInterval())
					r.makeMasterDownTimer()
					r.sendAdvertMessage()
					if err := r.deactivateManagedVIPs(); err != nil {
						logger.GLoger.Printf(logger.ERROR, "VirtualRouter.deactivateManagedVIPs: %v", err)
					}
					r.state = BACKUP
					r.transitionDoWork(Master2Backup)
				}
			}

		case BACKUP:
			var preemptDelayTimerC <-chan time.Time
			if r.preemptDelayTimer != nil {
				preemptDelayTimerC = r.preemptDelayTimer.C
			}
			select {
			case event := <-r.eventChannel:
				if event == SHUTDOWN {
					r.shutdownAll(Backup2Init)
					logger.GLoger.Printf(logger.INFO, "event %s received", event)
					return
				}
				if event == HEARTBEAT_DOWN {
					logger.GLoger.Printf(logger.INFO, "heartbeat interface %s down", r.heartbeatInterface)
					r.enterFault(Backup2Fault)
				}
			case packet := <-r.packetQueue: //process incoming advertisement
				r.handleBackupPacket(packet)
			case <-r.masterDownTimer.C: //Master_Down_Timer fired
				if r.drainBackupPackets(true) {
					continue
				}
				r.enterMaster(Backup2Master)
			case <-preemptDelayTimerC:
				if r.drainBackupPackets(false) {
					continue
				}
				r.enterMaster(Backup2Master)
			}
		case FAULT:
			select {
			case event := <-r.eventChannel:
				if event == SHUTDOWN {
					r.faultOwnsVIPs = false
					r.shutdownResources()
					r.state = INIT
					return
				}
				if event == HEARTBEAT_UP {
					r.faultOwnsVIPs = false
					if r.priority == 255 || r.owner {
						logger.GLoger.Printf(logger.INFO, "enter owner mode")
						r.enterMaster(Fault2Master)
						continue
					}
					logger.GLoger.Printf(logger.INFO, "VR is not the owner of protected IP addresses")
					r.enterBackup(Fault2Backup, true)
				}
			case <-r.packetQueue:
				continue
			}
		}
	}
}

func (vr *VirtualRouter) StartWithEventSelector() {
	go vr.fetchVRRPPacket()
	go vr.monitorHeartbeat()
	go func() {
		vr.eventChannel <- START
	}()

	vr.eventSelector()
}

func (vr *VirtualRouter) Stop() {
	vr.stopRequestOnce.Do(func() {
		select {
		case vr.eventChannel <- SHUTDOWN:
		default:
			go func() {
				select {
				case vr.eventChannel <- SHUTDOWN:
				case <-vr.stopSignal:
				}
			}()
		}
	})
}

// SetUnicastMode enables or disables unicast mode (RFC 5798)
// When enabled, VRRP advertisements will be sent to configured unicast peer addresses
// instead of the multicast address.SetUnicastMode must be called before StartWithEventSelector
func (vr *VirtualRouter) SetUnicastMode(enabled bool) *VirtualRouter {
	if len(vr.unicastPeers) == 0 && enabled {
		logger.GLoger.Printf(logger.ERROR, "SetUnicastMode: no unicast peers configured")
		return vr
	}
	vr.unicastMode = enabled
	if enabled {
		logger.GLoger.Printf(logger.INFO, "unicast mode enabled for virtual router %v", vr.vrID)
	} else {
		logger.GLoger.Printf(logger.INFO, "unicast mode disabled (multicast mode) for virtual router %v", vr.vrID)
	}
	var err error
	if vr.ipvX == IPv4 {
		//set up IPv4 interface
		if vr.unicastMode {
			vr.iplayerInterface, err = NewIPv4ConnUnicast(vr.preferredSourceIP, vr.unicastPeers[0])
		} else {
			vr.iplayerInterface, err = NewIPv4ConnMulticast(vr.preferredSourceIP, VRRPMultiAddrIPv4)
		}
	} else {
		//set up IPv6 interface
		if vr.unicastMode {
			vr.iplayerInterface, err = NewIPv6ConUnicast(vr.preferredSourceIP, vr.unicastPeers[0])
		} else {
			vr.iplayerInterface, err = NewIPv6ConMulticast(vr.preferredSourceIP, VRRPMultiAddrIPv6)
		}
	}
	if err != nil {
		logger.GLoger.Printf(logger.ERROR, "SetUnicastMode: failed to recreate IP connection: %v", err)
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
