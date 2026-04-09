package vrrp

import (
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/mdlayher/arp"
)

type mockARPClient struct {
	mu         sync.Mutex
	writeTimes []time.Time
	closed     bool
}

type mockAddrAnnouncer struct {
	mu     sync.Mutex
	closed bool
}

type mockIPConnection struct {
	mu     sync.Mutex
	closed bool
}

type recordingIPConnection struct {
	mockIPConnection
	writes int
}

func newBackupRouterForPreemptDelayTests(masterAdvertTicks uint16) *VirtualRouter {
	vr := &VirtualRouter{
		priority:              100,
		advertisementInterval: masterAdvertTicks,
		ipAddrAnnouncer:       &mockAddrAnnouncer{},
		iplayerInterface:      &mockIPConnection{},
		eventChannel:          make(chan EVENT, 1),
		packetQueue:           make(chan *VRRPPacket, 1),
		transitionHandler:     make(map[transition]func(int)),
		stopSignal:            make(chan struct{}),
		heartbeatInterface:    "eth0",
		preferredSourceIP:     net.IPv4(192, 0, 2, 10).To16(),
		protectedIPaddrs:      make(map[[16]byte]*net.Interface),
	}
	vr.setMasterAdvInterval(masterAdvertTicks)
	vr.state = BACKUP
	vr.makeMasterDownTimer()
	return vr
}

func makeAdvertPacket(priority byte, adv uint16, src net.IP) *VRRPPacket {
	packet := &VRRPPacket{
		Pshdr: &PseudoHeader{
			Saddr: src.To16(),
		},
		Header: [8]byte{
			0x30, // VRRPv3 advert by default; the tests only care about priority/interval.
			0,
			priority,
		},
	}
	packet.SetAdvertisementInterval(adv)
	return packet
}

func startRouterLoop(vr *VirtualRouter) chan struct{} {
	done := make(chan struct{})
	go func() {
		vr.eventSelector()
		close(done)
	}()
	return done
}

func stopRouterLoop(t *testing.T, vr *VirtualRouter, done chan struct{}) {
	t.Helper()
	vr.Stop()

	select {
	case <-done:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("eventSelector did not return after stopRouterLoop")
	}
}

func (m *mockARPClient) WriteTo(_ *arp.Packet, _ net.HardwareAddr) error {
	m.mu.Lock()
	m.writeTimes = append(m.writeTimes, time.Now())
	m.mu.Unlock()
	return nil
}

func (m *mockARPClient) Close() error {
	m.mu.Lock()
	m.closed = true
	m.mu.Unlock()
	return nil
}

func (m *mockARPClient) times() []time.Time {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]time.Time, len(m.writeTimes))
	copy(out, m.writeTimes)
	return out
}

func (m *mockARPClient) isClosed() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.closed
}

func (m *mockAddrAnnouncer) AnnounceAll(_ *VirtualRouter) error {
	return nil
}

func (m *mockAddrAnnouncer) Close() error {
	m.mu.Lock()
	m.closed = true
	m.mu.Unlock()
	return nil
}

func (m *mockAddrAnnouncer) isClosed() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.closed
}

func (m *mockIPConnection) WriteMessage(_ *VRRPPacket) error {
	return nil
}

func (m *mockIPConnection) WriteMessageTo(_ *VRRPPacket, _ net.IP) error {
	return nil
}

func (m *mockIPConnection) ReadMessage() (*VRRPPacket, error) {
	return nil, net.ErrClosed
}

func (m *mockIPConnection) Close() error {
	m.mu.Lock()
	m.closed = true
	m.mu.Unlock()
	return nil
}

func (m *mockIPConnection) isClosed() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.closed
}

func (m *recordingIPConnection) WriteMessage(_ *VRRPPacket) error {
	m.mu.Lock()
	m.writes++
	m.mu.Unlock()
	return nil
}

func (m *recordingIPConnection) WriteMessageTo(_ *VRRPPacket, _ net.IP) error {
	m.mu.Lock()
	m.writes++
	m.mu.Unlock()
	return nil
}

func (m *recordingIPConnection) writeCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.writes
}

func TestAssembleVRRPPacketForDestinationRecomputesChecksumPerPeer(t *testing.T) {
	vr := &VirtualRouter{
		vrID:                  42,
		priority:              150,
		advertisementInterval: 100,
		ipvX:                  IPv4,
		preferredSourceIP:     net.IPv4(192, 0, 2, 10).To16(),
		protectedIPaddrs:      make(map[[16]byte]*net.Interface),
	}

	vip := net.IPv4(192, 0, 2, 100).To16()
	var key [16]byte
	copy(key[:], vip)
	vr.protectedIPaddrs[key] = nil

	peer1 := net.IPv4(192, 0, 2, 1).To16()
	peer2 := net.IPv4(192, 0, 2, 2).To16()

	packet1 := vr.assembleVRRPPacketForDestination(peer1)
	packet2 := vr.assembleVRRPPacketForDestination(peer2)

	if packet1.GetCheckSum() == packet2.GetCheckSum() {
		t.Fatalf("expected distinct checksums for distinct unicast peers, got %x", packet1.GetCheckSum())
	}

	pshdr1 := &PseudoHeader{
		Saddr:    vr.preferredSourceIP,
		Daddr:    peer1,
		Protocol: VRRPIPProtocolNumber,
		Len:      uint16(len(packet1.ToBytes())),
	}
	if !packet1.ValidateCheckSum(pshdr1) {
		t.Fatal("packet for peer1 failed checksum validation against peer1 destination")
	}

	pshdr2 := &PseudoHeader{
		Saddr:    vr.preferredSourceIP,
		Daddr:    peer2,
		Protocol: VRRPIPProtocolNumber,
		Len:      uint16(len(packet2.ToBytes())),
	}
	if !packet2.ValidateCheckSum(pshdr2) {
		t.Fatal("packet for peer2 failed checksum validation against peer2 destination")
	}

	if packet1.ValidateCheckSum(pshdr2) {
		t.Fatal("packet for peer1 unexpectedly validated against peer2 destination")
	}
}

func TestIPv4GratuitousARPOperationDefaultsToRequest(t *testing.T) {
	var vr VirtualRouter
	if vr.garpOperation != GratuitousARPRequest {
		t.Fatalf("expected zero-value gratuitous ARP operation to be request, got %v", vr.garpOperation)
	}
}

func TestSetPreemptDelayStoresDuration(t *testing.T) {
	vr := &VirtualRouter{}
	delay := 250 * time.Millisecond

	returned := vr.SetPreemptDelay(delay)
	if returned != vr {
		t.Fatal("expected SetPreemptDelay to return the receiver")
	}
	if got := vr.preemptDelay; got != delay {
		t.Fatalf("expected preemptDelay to be %v, got %v", delay, got)
	}
}

func TestBackupPreemptDelayZeroPreservesCurrentTakeoverTiming(t *testing.T) {
	vr := newBackupRouterForPreemptDelayTests(10)
	vr.SetPreemptDelay(0)

	transitionCh := make(chan transition, 1)
	vr.Enroll(Backup2Master, func(int) {
		transitionCh <- Backup2Master
	})

	done := startRouterLoop(vr)
	defer stopRouterLoop(t, vr, done)

	withinTimer := time.Duration(vr.masterDownInterval) * 10 * time.Millisecond / 3
	select {
	case trans := <-transitionCh:
		t.Fatalf("unexpected transition before master-down expiry: %v", trans)
	case <-time.After(withinTimer):
	}

	if vr.preemptPending {
		t.Fatal("expected preemptPending to remain false before master-down expiry")
	}

	select {
	case trans := <-transitionCh:
		if trans != Backup2Master {
			t.Fatalf("expected Backup2Master transition after master-down expiry, got %v", trans)
		}
	case <-time.After(time.Duration(vr.masterDownInterval)*10*time.Millisecond + 100*time.Millisecond):
		t.Fatal("expected Backup2Master transition after master-down expiry")
	}

	if vr.preemptPending {
		t.Fatal("expected preemptPending to remain false after master-down expiry")
	}

	// The transition handler confirms takeover timing without racing the router state.
	// No direct state reads are needed here.
}

func TestMakeGratuitousPacketUsesConfiguredOperation(t *testing.T) {
	announcer := NewIPv4AddrAnnouncer()
	address := netip.MustParseAddr("192.0.2.100")
	hardwareAddr := net.HardwareAddr{0x00, 0x00, 0x5e, 0x00, 0x01, 0x2a}

	requestPacket, err := announcer.makeGratuitousPacket(address, hardwareAddr, GratuitousARPRequest)
	if err != nil {
		t.Fatalf("request packet creation failed: %v", err)
	}
	if requestPacket.Operation != arp.OperationRequest {
		t.Fatalf("expected gratuitous ARP request, got %v", requestPacket.Operation)
	}

	replyPacket, err := announcer.makeGratuitousPacket(address, hardwareAddr, GratuitousARPReply)
	if err != nil {
		t.Fatalf("reply packet creation failed: %v", err)
	}
	if replyPacket.Operation != arp.OperationReply {
		t.Fatalf("expected gratuitous ARP reply, got %v", replyPacket.Operation)
	}

	if !net.IP(requestPacket.SenderIP.AsSlice()).Equal(net.IP(replyPacket.SenderIP.AsSlice())) {
		t.Fatal("request/reply packets should announce the same IP address")
	}
}

func TestARPInterfaceSenderSerializesWithThrottle(t *testing.T) {
	mockClient := &mockARPClient{}
	sender := newARPInterfaceSender(mockClient, 15*time.Millisecond)

	err := sender.enqueue(&arp.Packet{Operation: arp.OperationRequest})
	if err != nil {
		t.Fatalf("first enqueue failed: %v", err)
	}
	err = sender.enqueue(&arp.Packet{Operation: arp.OperationRequest})
	if err != nil {
		t.Fatalf("second enqueue failed: %v", err)
	}

	var writeTimes []time.Time
	deadline := time.Now().Add(300 * time.Millisecond)
	for time.Now().Before(deadline) {
		writeTimes = mockClient.times()
		if len(writeTimes) == 2 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if len(writeTimes) != 2 {
		t.Fatalf("expected 2 serialized writes, got %d", len(writeTimes))
	}

	if delta := writeTimes[1].Sub(writeTimes[0]); delta < 10*time.Millisecond {
		t.Fatalf("expected throttled spacing between queued writes, got %v", delta)
	}
}

func TestARPInterfaceSenderCloseReleasesClientAndRejectsEnqueue(t *testing.T) {
	mockClient := &mockARPClient{}
	sender := newARPInterfaceSender(mockClient, 0)

	err := sender.enqueue(&arp.Packet{Operation: arp.OperationRequest})
	if err != nil {
		t.Fatalf("enqueue before close failed: %v", err)
	}

	if err := sender.close(); err != nil {
		t.Fatalf("sender close failed: %v", err)
	}
	if err := sender.close(); err != nil {
		t.Fatalf("sender close should be idempotent: %v", err)
	}
	if !mockClient.isClosed() {
		t.Fatal("expected sender close to close underlying ARP client")
	}

	if err := sender.enqueue(&arp.Packet{Operation: arp.OperationRequest}); err == nil {
		t.Fatal("expected enqueue on closed sender to fail")
	}
}

func TestEventSelectorShutdownClosesResourcesAndReturns(t *testing.T) {
	announcer := &mockAddrAnnouncer{}
	conn := &mockIPConnection{}
	timer := time.NewTimer(time.Minute)
	defer timer.Stop()

	vr := &VirtualRouter{
		state:             BACKUP,
		ipAddrAnnouncer:   announcer,
		iplayerInterface:  conn,
		eventChannel:      make(chan EVENT, 1),
		packetQueue:       make(chan *VRRPPacket, 1),
		transitionHandler: make(map[transition]func(int)),
		masterDownTimer:   timer,
		stopSignal:        make(chan struct{}),
	}

	done := make(chan struct{})
	go func() {
		vr.eventSelector()
		close(done)
	}()

	vr.eventChannel <- SHUTDOWN

	select {
	case <-done:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("eventSelector did not return after shutdown")
	}

	if !announcer.isClosed() {
		t.Fatal("expected shutdown to close announcer")
	}
	if !conn.isClosed() {
		t.Fatal("expected shutdown to close IP connection")
	}
	if !vr.isStopping() {
		t.Fatal("expected shutdown to close stop signal")
	}
}

func TestStopIsIdempotentAndNonBlocking(t *testing.T) {
	vr := &VirtualRouter{
		eventChannel: make(chan EVENT, 1),
		stopSignal:   make(chan struct{}),
	}
	vr.eventChannel <- START

	done := make(chan struct{})
	go func() {
		vr.Stop()
		vr.Stop()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(200 * time.Millisecond):
		t.Fatal("Stop blocked when event channel was full")
	}

	vr.shutdownResources()
}

func TestHeartbeatDownTransitionsToFaultAndRecoveryReturnsToBackupForNonOwner(t *testing.T) {
	announcer := &mockAddrAnnouncer{}
	conn := &mockIPConnection{}
	timer := time.NewTimer(time.Minute)
	defer timer.Stop()

	vr := &VirtualRouter{
		state:                 BACKUP,
		priority:              100,
		advertisementInterval: 100,
		ipAddrAnnouncer:       announcer,
		iplayerInterface:      conn,
		eventChannel:          make(chan EVENT, 4),
		packetQueue:           make(chan *VRRPPacket, 1),
		transitionHandler:     make(map[transition]func(int)),
		masterDownTimer:       timer,
		stopSignal:            make(chan struct{}),
		heartbeatInterface:    "eth0",
		protectedIPaddrs:      make(map[[16]byte]*net.Interface),
	}

	vr.setHeartbeatStatus(true)

	done := make(chan struct{})
	go func() {
		vr.eventSelector()
		close(done)
	}()

	vr.eventChannel <- HEARTBEAT_DOWN
	time.Sleep(50 * time.Millisecond)
	if vr.state != FAULT {
		t.Fatalf("expected heartbeat down to move router into FAULT, got %d", vr.state)
	}
	if vr.faultOwnsVIPs {
		t.Fatal("expected non-owner FAULT state to release VIP ownership")
	}

	vr.eventChannel <- HEARTBEAT_UP
	time.Sleep(50 * time.Millisecond)
	if vr.state != BACKUP {
		t.Fatalf("expected non-owner recovery to return to BACKUP, got %d", vr.state)
	}

	vr.eventChannel <- SHUTDOWN
	select {
	case <-done:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("eventSelector did not return after shutdown")
	}
}

func TestHeartbeatDownWithMasterOverrideStaysInFaultAndOwnsVIPs(t *testing.T) {
	announcer := &mockAddrAnnouncer{}
	conn := &mockIPConnection{}
	timer := time.NewTimer(time.Minute)
	defer timer.Stop()

	vr := &VirtualRouter{
		state:                 BACKUP,
		priority:              100,
		advertisementInterval: 100,
		ipAddrAnnouncer:       announcer,
		iplayerInterface:      conn,
		eventChannel:          make(chan EVENT, 4),
		packetQueue:           make(chan *VRRPPacket, 1),
		transitionHandler:     make(map[transition]func(int)),
		masterDownTimer:       timer,
		stopSignal:            make(chan struct{}),
		heartbeatInterface:    "eth0",
		heartbeatDownMaster:   true,
		protectedIPaddrs:      make(map[[16]byte]*net.Interface),
	}
	vr.setHeartbeatStatus(true)

	done := make(chan struct{})
	go func() {
		vr.eventSelector()
		close(done)
	}()

	vr.eventChannel <- HEARTBEAT_DOWN
	time.Sleep(50 * time.Millisecond)
	if vr.state != FAULT {
		t.Fatalf("expected heartbeat down override to enter FAULT, got %d", vr.state)
	}
	if !vr.faultOwnsVIPs {
		t.Fatal("expected heartbeatDownMaster to retain VIP ownership while in FAULT")
	}

	vr.eventChannel <- HEARTBEAT_UP
	time.Sleep(50 * time.Millisecond)
	if vr.state != BACKUP {
		t.Fatalf("expected non-owner recovery to return to BACKUP, got %d", vr.state)
	}

	vr.eventChannel <- SHUTDOWN
	select {
	case <-done:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("eventSelector did not return after shutdown")
	}
}

func TestSendAdvertMessageSkipsFaultState(t *testing.T) {
	conn := &recordingIPConnection{}
	vr := &VirtualRouter{
		state:            FAULT,
		iplayerInterface: conn,
		protectedIPaddrs: make(map[[16]byte]*net.Interface),
	}

	vr.sendAdvertMessage()

	if conn.writeCount() != 0 {
		t.Fatalf("expected no adverts to be sent in FAULT, got %d writes", conn.writeCount())
	}
}

func TestFaultStateIgnoresIncomingAdvertisements(t *testing.T) {
	announcer := &mockAddrAnnouncer{}
	conn := &recordingIPConnection{}

	vr := &VirtualRouter{
		state:                 FAULT,
		priority:              100,
		advertisementInterval: 100,
		ipAddrAnnouncer:       announcer,
		iplayerInterface:      conn,
		eventChannel:          make(chan EVENT, 4),
		packetQueue:           make(chan *VRRPPacket, 1),
		transitionHandler:     make(map[transition]func(int)),
		stopSignal:            make(chan struct{}),
		heartbeatInterface:    "eth0",
		protectedIPaddrs:      make(map[[16]byte]*net.Interface),
	}
	vr.setHeartbeatStatus(false)

	packet := &VRRPPacket{}
	packet.SetPriority(200)
	packet.Pshdr = &PseudoHeader{Saddr: net.IPv4(192, 0, 2, 2).To16()}

	done := make(chan struct{})
	go func() {
		vr.eventSelector()
		close(done)
	}()

	vr.packetQueue <- packet
	time.Sleep(50 * time.Millisecond)
	if vr.state != FAULT {
		t.Fatalf("expected router to remain in FAULT after advertisement, got %d", vr.state)
	}
	if conn.writeCount() != 0 {
		t.Fatalf("expected FAULT to ignore advertisements without sending replies, got %d writes", conn.writeCount())
	}

	vr.eventChannel <- SHUTDOWN
	select {
	case <-done:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("eventSelector did not return after shutdown")
	}
}

func TestFaultShutdownDoesNotSendPriorityZeroAdvertisement(t *testing.T) {
	announcer := &mockAddrAnnouncer{}
	conn := &recordingIPConnection{}

	vr := &VirtualRouter{
		state:            FAULT,
		ipAddrAnnouncer:  announcer,
		iplayerInterface: conn,
		eventChannel:     make(chan EVENT, 1),
		packetQueue:      make(chan *VRRPPacket, 1),
		stopSignal:       make(chan struct{}),
	}

	done := make(chan struct{})
	go func() {
		vr.eventSelector()
		close(done)
	}()

	vr.eventChannel <- SHUTDOWN

	select {
	case <-done:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("eventSelector did not return after shutdown")
	}

	if conn.writeCount() != 0 {
		t.Fatalf("expected shutdown from FAULT to avoid advert sends, got %d writes", conn.writeCount())
	}
}

func TestHeartbeatUpRecoversOwnerFromFaultToMasterAndSendsAdvert(t *testing.T) {
	announcer := &mockAddrAnnouncer{}
	conn := &recordingIPConnection{}

	vr := &VirtualRouter{
		state:                 FAULT,
		owner:                 true,
		priority:              255,
		advertisementInterval: 100,
		ipAddrAnnouncer:       announcer,
		iplayerInterface:      conn,
		eventChannel:          make(chan EVENT, 1),
		packetQueue:           make(chan *VRRPPacket, 1),
		transitionHandler:     make(map[transition]func(int)),
		stopSignal:            make(chan struct{}),
		heartbeatInterface:    "eth0",
		protectedIPaddrs:      make(map[[16]byte]*net.Interface),
	}

	done := make(chan struct{})
	go func() {
		vr.eventSelector()
		close(done)
	}()

	vr.eventChannel <- HEARTBEAT_UP
	time.Sleep(50 * time.Millisecond)

	if vr.state != MASTER {
		t.Fatalf("expected owner recovery to return to MASTER, got %d", vr.state)
	}
	if conn.writeCount() == 0 {
		t.Fatal("expected owner recovery from FAULT to send an advertisement")
	}

	vr.eventChannel <- SHUTDOWN
	select {
	case <-done:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("eventSelector did not return after shutdown")
	}
}
