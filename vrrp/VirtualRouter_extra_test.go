package vrrp

import (
	"net"
	"testing"
	"time"
)

func TestLargerThanIPv4(t *testing.T) {
	tests := []struct {
		ip1, ip2 net.IP
		want     bool
	}{
		{net.IPv4(10, 0, 0, 2).To4(), net.IPv4(10, 0, 0, 1).To4(), true},
		{net.IPv4(10, 0, 0, 1).To4(), net.IPv4(10, 0, 0, 2).To4(), false},
		{net.IPv4(10, 0, 0, 1).To4(), net.IPv4(10, 0, 0, 1).To4(), false},
		{net.IPv4(10, 0, 1, 0).To4(), net.IPv4(10, 0, 0, 255).To4(), true},
		{net.IPv4(255, 255, 255, 255).To4(), net.IPv4(0, 0, 0, 0).To4(), true},
	}
	for _, tt := range tests {
		got := largerThan(tt.ip1, tt.ip2)
		if got != tt.want {
			t.Errorf("largerThan(%v, %v) = %v, want %v", tt.ip1, tt.ip2, got, tt.want)
		}
	}
}

func TestLargerThanMismatchedLength(t *testing.T) {
	// Different lengths returns false
	ip4 := net.IPv4(10, 0, 0, 1).To4()
	ip16 := net.IPv4(10, 0, 0, 1).To16()
	if largerThan(ip4, ip16) {
		t.Fatal("expected false for mismatched lengths")
	}
}

func TestSetPriorityOwnerIgnored(t *testing.T) {
	vr := &VirtualRouter{owner: true, priority: 255}
	result := vr.SetPriority(100)
	if result != vr {
		t.Fatal("expected SetPriority to return receiver")
	}
	if vr.priority != 255 {
		t.Fatal("expected owner priority to remain 255")
	}
}

func TestSetPriorityNonOwner(t *testing.T) {
	vr := &VirtualRouter{owner: false, priority: 100}
	vr.SetPriority(200)
	if vr.priority != 200 {
		t.Fatalf("expected priority 200, got %d", vr.priority)
	}
}

func TestSetPreemptMode(t *testing.T) {
	vr := &VirtualRouter{}
	result := vr.SetPreemptMode(false)
	if result != vr {
		t.Fatal("expected SetPreemptMode to return receiver")
	}
	if vr.preempt {
		t.Fatal("expected preempt to be false")
	}
	vr.SetPreemptMode(true)
	if !vr.preempt {
		t.Fatal("expected preempt to be true")
	}
}

func TestSetPreemptDelayNegativePanics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic for negative preempt delay")
		}
	}()
	vr := &VirtualRouter{}
	vr.SetPreemptDelay(-1 * time.Second)
}

func TestSetAdvInterval(t *testing.T) {
	vr := &VirtualRouter{}
	result := vr.SetAdvInterval(100 * time.Millisecond)
	if result != vr {
		t.Fatal("expected SetAdvInterval to return receiver")
	}
	if vr.advertisementInterval != 10 {
		t.Fatalf("expected interval 10, got %d", vr.advertisementInterval)
	}
}

func TestSetAdvIntervalTooSmallPanics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic for interval < 10ms")
		}
	}()
	vr := &VirtualRouter{}
	vr.SetAdvInterval(5 * time.Millisecond)
}

func TestSetPriorityAndMasterAdvInterval(t *testing.T) {
	vr := &VirtualRouter{}
	result := vr.SetPriorityAndMasterAdvInterval(150, 200*time.Millisecond)
	if result != vr {
		t.Fatal("expected to return receiver")
	}
	if vr.priority != 150 {
		t.Fatalf("expected priority 150, got %d", vr.priority)
	}
	if vr.advertisementIntervalOfMaster != 20 {
		t.Fatalf("expected master adv interval 20, got %d", vr.advertisementIntervalOfMaster)
	}
}

func TestSetPriorityAndMasterAdvIntervalPanics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic for interval < 10ms")
		}
	}()
	vr := &VirtualRouter{}
	vr.SetPriorityAndMasterAdvInterval(100, 1*time.Millisecond)
}

func TestSetMasterAdvIntervalComputesTimers(t *testing.T) {
	vr := &VirtualRouter{priority: 100}
	vr.setMasterAdvInterval(100)
	if vr.advertisementIntervalOfMaster != 100 {
		t.Fatalf("expected 100, got %d", vr.advertisementIntervalOfMaster)
	}
	// skewTime = interval - interval * priority / 256
	var interval float32 = 100
	var priority float32 = 100
	expectedSkew := uint16(interval) - uint16(interval*priority/256)
	if vr.skewTime != expectedSkew {
		t.Fatalf("expected skewTime %d, got %d", expectedSkew, vr.skewTime)
	}
	// masterDownInterval = 3 * interval + skewTime
	expectedMDI := 3*uint16(100) + expectedSkew
	if vr.masterDownInterval != expectedMDI {
		t.Fatalf("expected masterDownInterval %d, got %d", expectedMDI, vr.masterDownInterval)
	}
}

func TestEnrollOverwrite(t *testing.T) {
	vr := &VirtualRouter{
		transitionHandler: make(map[transition]func(int)),
	}
	called1 := false
	called2 := false

	overwritten := vr.Enroll(Backup2Master, func(int) { called1 = true })
	if overwritten {
		t.Fatal("expected first enrollment to return false")
	}

	overwritten = vr.Enroll(Backup2Master, func(int) { called2 = true })
	if !overwritten {
		t.Fatal("expected second enrollment to return true (overwrite)")
	}

	vr.transitionDoWork(Backup2Master)
	if called1 {
		t.Fatal("expected first handler to be overwritten")
	}
	if !called2 {
		t.Fatal("expected second handler to be called")
	}
}

func TestTransitionDoWorkUnregistered(t *testing.T) {
	vr := &VirtualRouter{
		transitionHandler: make(map[transition]func(int)),
	}
	// Should not panic for unregistered transition
	vr.transitionDoWork(Backup2Master)
}

func TestSetGratuitousARPOperation(t *testing.T) {
	vr := &VirtualRouter{}
	result := vr.SetGratuitousARPOperation(GratuitousARPReply)
	if result != vr {
		t.Fatal("expected to return receiver")
	}
	if vr.garpOperation != GratuitousARPReply {
		t.Fatal("expected garpOperation to be Reply")
	}
}

func TestSetGratuitousARPOperationInvalid(t *testing.T) {
	vr := &VirtualRouter{garpOperation: GratuitousARPRequest}
	vr.SetGratuitousARPOperation(GratuitousARPOperation(99))
	if vr.garpOperation != GratuitousARPRequest {
		t.Fatal("expected invalid operation to be ignored")
	}
}

func TestSetGratuitousARPThrottleInterval(t *testing.T) {
	vr := &VirtualRouter{}
	result := vr.SetGratuitousARPThrottleInterval(50 * time.Millisecond)
	if result != vr {
		t.Fatal("expected to return receiver")
	}
	if vr.garpThrottleInterval != 50*time.Millisecond {
		t.Fatalf("expected 50ms, got %v", vr.garpThrottleInterval)
	}
}

func TestSetGratuitousARPThrottleIntervalNegativeIgnored(t *testing.T) {
	vr := &VirtualRouter{garpThrottleInterval: 10 * time.Millisecond}
	vr.SetGratuitousARPThrottleInterval(-1 * time.Second)
	if vr.garpThrottleInterval != 10*time.Millisecond {
		t.Fatal("expected negative interval to be ignored")
	}
}

func TestSetHeartbeatDownMaster(t *testing.T) {
	vr := &VirtualRouter{}
	result := vr.SetHeartbeatDownMaster(true)
	if result != vr {
		t.Fatal("expected to return receiver")
	}
	if !vr.heartbeatDownMaster {
		t.Fatal("expected heartbeatDownMaster to be true")
	}
}

func TestSendAdvertMessageUnicastMode(t *testing.T) {
	conn := &recordingIPConnection{}
	vr := &VirtualRouter{
		state:             MASTER,
		unicastMode:       true,
		ipvX:              IPv4,
		preferredSourceIP: net.IPv4(192, 0, 2, 10).To16(),
		protectedIPaddrs:  make(map[[16]byte]*net.Interface),
		iplayerInterface:  conn,
		unicastPeers: []net.IP{
			net.IPv4(192, 0, 2, 1).To16(),
			net.IPv4(192, 0, 2, 2).To16(),
		},
	}
	vr.sendAdvertMessage()
	if conn.writeCount() != 2 {
		t.Fatalf("expected 2 writes (one per peer), got %d", conn.writeCount())
	}
}

func TestSendAdvertMessageMulticastMode(t *testing.T) {
	conn := &recordingIPConnection{}
	vr := &VirtualRouter{
		state:             MASTER,
		unicastMode:       false,
		ipvX:              IPv4,
		preferredSourceIP: net.IPv4(192, 0, 2, 10).To16(),
		protectedIPaddrs:  make(map[[16]byte]*net.Interface),
		iplayerInterface:  conn,
	}
	vr.sendAdvertMessage()
	if conn.writeCount() != 1 {
		t.Fatalf("expected 1 multicast write, got %d", conn.writeCount())
	}
}

func TestAddIPvXAddrDuplicate(t *testing.T) {
	vr := &VirtualRouter{
		protectedIPaddrs: make(map[[16]byte]*net.Interface),
		interfaceByName: func(name string) (*net.Interface, error) {
			return &net.Interface{Name: name, Index: 1}, nil
		},
	}
	ip := net.IPv4(10, 0, 0, 1)
	err := vr.AddIPvXAddr("eth0", ip)
	if err != nil {
		t.Fatalf("first AddIPvXAddr failed: %v", err)
	}
	// Adding same IP again should succeed but not duplicate
	err = vr.AddIPvXAddr("eth0", ip)
	if err != nil {
		t.Fatalf("duplicate AddIPvXAddr should not error: %v", err)
	}
	if len(vr.protectedIPaddrs) != 1 {
		t.Fatalf("expected 1 protected IP, got %d", len(vr.protectedIPaddrs))
	}
}

func TestRemoveIPvXAddr(t *testing.T) {
	vr := &VirtualRouter{
		protectedIPaddrs: make(map[[16]byte]*net.Interface),
		interfaceByName: func(name string) (*net.Interface, error) {
			return &net.Interface{Name: name, Index: 1}, nil
		},
	}
	ip := net.IPv4(10, 0, 0, 1)
	vr.AddIPvXAddr("eth0", ip)
	vr.RemoveIPvXAddr(ip.To16())
	if len(vr.protectedIPaddrs) != 0 {
		t.Fatal("expected protected IP to be removed")
	}
}

func TestRemoveIPvXAddrNonExistent(t *testing.T) {
	vr := &VirtualRouter{
		protectedIPaddrs: make(map[[16]byte]*net.Interface),
	}
	// Should not panic
	vr.RemoveIPvXAddr(net.IPv4(10, 0, 0, 1).To16())
}

func TestIsStoppingBeforeAndAfterShutdown(t *testing.T) {
	vr := &VirtualRouter{
		stopSignal: make(chan struct{}),
	}
	if vr.isStopping() {
		t.Fatal("expected not stopping initially")
	}
	close(vr.stopSignal)
	if !vr.isStopping() {
		t.Fatal("expected stopping after close")
	}
}

func TestHeartbeatStatusAndSetHeartbeatStatus(t *testing.T) {
	vr := &VirtualRouter{}
	up, known := vr.heartbeatStatus()
	if known {
		t.Fatal("expected heartbeat not known initially")
	}
	if up {
		t.Fatal("expected heartbeat not up initially")
	}

	vr.setHeartbeatStatus(true)
	up, known = vr.heartbeatStatus()
	if !known {
		t.Fatal("expected heartbeat known after set")
	}
	if !up {
		t.Fatal("expected heartbeat up")
	}

	vr.setHeartbeatStatus(false)
	up, known = vr.heartbeatStatus()
	if !known {
		t.Fatal("expected heartbeat still known")
	}
	if up {
		t.Fatal("expected heartbeat down")
	}
}

func TestCloseAnnouncerNil(t *testing.T) {
	vr := &VirtualRouter{}
	// Should not panic
	vr.closeAnnouncer()
}

func TestCloseIPConnectionNil(t *testing.T) {
	vr := &VirtualRouter{}
	// Should not panic
	vr.closeIPConnection()
}

func TestStopStateTimersAllNil(t *testing.T) {
	vr := &VirtualRouter{}
	// Should not panic with all nil timers
	vr.stopStateTimers()
}

func TestStopAdvertTickerNil(t *testing.T) {
	vr := &VirtualRouter{}
	// Should not panic
	vr.stopAdvertTicker()
}

func TestStopMasterDownTimerNil(t *testing.T) {
	vr := &VirtualRouter{}
	// Should not panic
	vr.stopMasterDownTimer()
}

func TestMakeMasterDownTimerCreatesThenResets(t *testing.T) {
	vr := &VirtualRouter{masterDownInterval: 10}
	vr.makeMasterDownTimer()
	if vr.masterDownTimer == nil {
		t.Fatal("expected timer to be created")
	}
	// Calling again should reset rather than create new
	vr.makeMasterDownTimer()
	if vr.masterDownTimer == nil {
		t.Fatal("expected timer to still exist after reset")
	}
	vr.masterDownTimer.Stop()
}

func TestResetMasterDownTimerFromNil(t *testing.T) {
	vr := &VirtualRouter{masterDownInterval: 10}
	vr.resetMasterDownTimer()
	if vr.masterDownTimer == nil {
		t.Fatal("expected timer to be created from nil")
	}
	vr.masterDownTimer.Stop()
}

func TestResetMasterDownTimerToSkewTimeFromNil(t *testing.T) {
	vr := &VirtualRouter{skewTime: 5}
	vr.resetMasterDownTimerToSkewTime()
	if vr.masterDownTimer == nil {
		t.Fatal("expected timer to be created from nil")
	}
	vr.masterDownTimer.Stop()
}

func TestMakeGarpTimerCreatesThenResets(t *testing.T) {
	vr := &VirtualRouter{}
	vr.makeGarpTimer(1)
	if vr.gratuitousArpTimer == nil {
		t.Fatal("expected garp timer to be created")
	}
	// Calling again should reset
	vr.makeGarpTimer(2)
	if vr.gratuitousArpTimer == nil {
		t.Fatal("expected garp timer to still exist after reset")
	}
	vr.gratuitousArpTimer.Stop()
}

func TestStopGarpTimerNil(t *testing.T) {
	vr := &VirtualRouter{}
	// Should not panic
	vr.stopGarpTimer()
}

func TestStopPreemptDelayTimerNilClearsState(t *testing.T) {
	vr := &VirtualRouter{preemptPending: true}
	vr.stopPreemptDelayTimer()
	if vr.preemptPending {
		t.Fatal("expected preemptPending to be cleared")
	}
}

func TestMakePreemptDelayTimerZeroDelayNoOp(t *testing.T) {
	vr := &VirtualRouter{preemptDelay: 0}
	vr.makePreemptDelayTimer()
	if vr.preemptDelayTimer != nil {
		t.Fatal("expected no timer for zero delay")
	}
}

func TestMakePreemptDelayTimerResetsExisting(t *testing.T) {
	vr := &VirtualRouter{preemptDelay: 100 * time.Millisecond}
	vr.makePreemptDelayTimer()
	if vr.preemptDelayTimer == nil {
		t.Fatal("expected timer to be created")
	}
	timer1 := vr.preemptDelayTimer
	// Calling again should reuse/reset
	vr.makePreemptDelayTimer()
	if vr.preemptDelayTimer != timer1 {
		t.Fatal("expected same timer object to be reused")
	}
	vr.preemptDelayTimer.Stop()
}

func TestAssembleVRRPPacketIPv4(t *testing.T) {
	vr := &VirtualRouter{
		vrID:                  42,
		priority:              150,
		advertisementInterval: 100,
		ipvX:                  IPv4,
		preferredSourceIP:     net.IPv4(192, 0, 2, 10).To16(),
		protectedIPaddrs:      make(map[[16]byte]*net.Interface),
	}
	ip := net.IPv4(192, 0, 2, 100).To16()
	var key [16]byte
	copy(key[:], ip)
	vr.protectedIPaddrs[key] = nil

	pkt := vr.assembleVRRPPacket()
	if pkt.GetVersion() != byte(VRRPv3) {
		t.Fatalf("expected version 3, got %d", pkt.GetVersion())
	}
	if pkt.GetVirtualRouterID() != 42 {
		t.Fatalf("expected VRID 42, got %d", pkt.GetVirtualRouterID())
	}
	if pkt.GetPriority() != 150 {
		t.Fatalf("expected priority 150, got %d", pkt.GetPriority())
	}
	if pkt.GetIPvXAddrCount() != 1 {
		t.Fatalf("expected 1 address, got %d", pkt.GetIPvXAddrCount())
	}
	if pkt.GetCheckSum() == 0 {
		t.Fatal("expected non-zero checksum")
	}
}

func TestAssembleVRRPPacketIPv6(t *testing.T) {
	vr := &VirtualRouter{
		vrID:                  10,
		priority:              200,
		advertisementInterval: 50,
		ipvX:                  IPv6,
		preferredSourceIP:     net.ParseIP("2001:db8::100"),
		protectedIPaddrs:      make(map[[16]byte]*net.Interface),
	}
	ip := net.ParseIP("2001:db8::1")
	var key [16]byte
	copy(key[:], ip)
	vr.protectedIPaddrs[key] = nil

	pkt := vr.assembleVRRPPacket()
	if pkt.GetIPvXAddrCount() != 1 {
		t.Fatalf("expected 1 IPv6 address, got %d", pkt.GetIPvXAddrCount())
	}
}

func TestUnicastPeerManagement(t *testing.T) {
	vr := &VirtualRouter{
		ipvX:         IPv4,
		unicastPeers: make([]net.IP, 0),
	}

	// Add peers
	vr.AddUnicastPeer(net.IPv4(10, 0, 0, 1))
	vr.AddUnicastPeer(net.IPv4(10, 0, 0, 2))
	if len(vr.unicastPeers) != 2 {
		t.Fatalf("expected 2 peers, got %d", len(vr.unicastPeers))
	}

	// Add duplicate
	vr.AddUnicastPeer(net.IPv4(10, 0, 0, 1))
	if len(vr.unicastPeers) != 2 {
		t.Fatalf("expected 2 peers after duplicate, got %d", len(vr.unicastPeers))
	}

	// GetUnicastPeers returns a copy
	peers := vr.GetUnicastPeers()
	if len(peers) != 2 {
		t.Fatalf("expected 2 peers from getter, got %d", len(peers))
	}

	// Remove a peer
	vr.RemoveUnicastPeer(net.IPv4(10, 0, 0, 1))
	if len(vr.unicastPeers) != 1 {
		t.Fatalf("expected 1 peer after removal, got %d", len(vr.unicastPeers))
	}

	// Remove non-existent peer (should not panic)
	vr.RemoveUnicastPeer(net.IPv4(10, 0, 0, 99))
	if len(vr.unicastPeers) != 1 {
		t.Fatal("expected peer count unchanged")
	}

	// Clear all peers
	vr.ClearUnicastPeers()
	if len(vr.unicastPeers) != 0 {
		t.Fatal("expected 0 peers after clear")
	}
}

func TestAddUnicastPeerVersionMismatch(t *testing.T) {
	vr := &VirtualRouter{
		ipvX:         IPv4,
		unicastPeers: make([]net.IP, 0),
	}
	// Add IPv6 peer to IPv4 router
	vr.AddUnicastPeer(net.ParseIP("2001:db8::1"))
	if len(vr.unicastPeers) != 0 {
		t.Fatal("expected IPv6 peer to be rejected for IPv4 router")
	}

	vr6 := &VirtualRouter{
		ipvX:         IPv6,
		unicastPeers: make([]net.IP, 0),
	}
	// Add IPv4 peer to IPv6 router
	vr6.AddUnicastPeer(net.IPv4(10, 0, 0, 1))
	if len(vr6.unicastPeers) != 0 {
		t.Fatal("expected IPv4 peer to be rejected for IPv6 router")
	}
}

func TestIsUnicastMode(t *testing.T) {
	vr := &VirtualRouter{unicastMode: false}
	if vr.IsUnicastMode() {
		t.Fatal("expected multicast mode")
	}
	vr.unicastMode = true
	if !vr.IsUnicastMode() {
		t.Fatal("expected unicast mode")
	}
}

func TestSetUnicastModeNoPeersIgnored(t *testing.T) {
	vr := &VirtualRouter{
		unicastPeers: make([]net.IP, 0),
	}
	result := vr.SetUnicastMode(true)
	if result != vr {
		t.Fatal("expected to return receiver")
	}
	if vr.unicastMode {
		t.Fatal("expected unicast mode to remain disabled without peers")
	}
}

func TestMakeAdvertTickerAndStop(t *testing.T) {
	vr := &VirtualRouter{advertisementInterval: 10}
	vr.makeAdvertTicker()
	if vr.advertisementTicker == nil {
		t.Fatal("expected ticker to be created")
	}
	vr.stopAdvertTicker()
	// Multiple stops should be safe
	vr.stopAdvertTicker()
}

func TestEventSelectorInitShutdown(t *testing.T) {
	announcer := &mockAddrAnnouncer{}
	conn := &mockIPConnection{}
	vr := &VirtualRouter{
		state:             INIT,
		ipAddrAnnouncer:   announcer,
		iplayerInterface:  conn,
		eventChannel:      make(chan EVENT, 1),
		packetQueue:       make(chan *VRRPPacket, 1),
		transitionHandler: make(map[transition]func(int)),
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
		t.Fatal("eventSelector did not return after INIT shutdown")
	}
}

func TestEventSelectorMasterShutdownSendsPriority0(t *testing.T) {
	conn := &recordingIPConnection{}
	vr := &VirtualRouter{
		state:                 MASTER,
		priority:              100,
		advertisementInterval: 100,
		ipvX:                  IPv4,
		preferredSourceIP:     net.IPv4(192, 0, 2, 10).To16(),
		ipAddrAnnouncer:       &mockAddrAnnouncer{},
		iplayerInterface:      conn,
		eventChannel:          make(chan EVENT, 1),
		packetQueue:           make(chan *VRRPPacket, 1),
		transitionHandler:     make(map[transition]func(int)),
		advertisementTicker:   time.NewTicker(time.Minute),
		gratuitousArpTimer:    time.NewTimer(time.Minute),
		stopSignal:            make(chan struct{}),
		protectedIPaddrs:      make(map[[16]byte]*net.Interface),
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
		t.Fatal("eventSelector did not return after MASTER shutdown")
	}

	if conn.writeCount() == 0 {
		t.Fatal("expected MASTER shutdown to send priority-0 advertisement")
	}
}

func TestMasterReceivesHigherPriorityTransitionsToBackup(t *testing.T) {
	conn := &recordingIPConnection{}
	announcer := &mockAddrAnnouncer{}
	vr := &VirtualRouter{
		state:                 MASTER,
		priority:              100,
		advertisementInterval: 100,
		ipvX:                  IPv4,
		preferredSourceIP:     net.IPv4(192, 0, 2, 10).To16(),
		ipAddrAnnouncer:       announcer,
		iplayerInterface:      conn,
		eventChannel:          make(chan EVENT, 1),
		packetQueue:           make(chan *VRRPPacket, 2),
		transitionHandler:     make(map[transition]func(int)),
		advertisementTicker:   time.NewTicker(time.Minute),
		gratuitousArpTimer:    time.NewTimer(time.Minute),
		stopSignal:            make(chan struct{}),
		protectedIPaddrs:      make(map[[16]byte]*net.Interface),
	}

	transitionCh := make(chan transition, 1)
	vr.Enroll(Master2Backup, func(int) {
		transitionCh <- Master2Backup
	})

	done := startRouterLoop(vr)
	defer stopRouterLoop(t, vr, done)

	// Send a higher priority packet
	pkt := makeAdvertPacket(200, 100, net.IPv4(192, 0, 2, 20))
	vr.packetQueue <- pkt

	expectTransition(t, transitionCh, Master2Backup, 500*time.Millisecond)
}

func TestMasterTieBreakerLossTransitionsToBackup(t *testing.T) {
	conn := &recordingIPConnection{}
	announcer := &mockAddrAnnouncer{}
	vr := &VirtualRouter{
		state:                 MASTER,
		priority:              100,
		advertisementInterval: 100,
		ipvX:                  IPv4,
		preferredSourceIP:     net.IPv4(192, 0, 2, 10).To16(),
		ipAddrAnnouncer:       announcer,
		iplayerInterface:      conn,
		eventChannel:          make(chan EVENT, 1),
		packetQueue:           make(chan *VRRPPacket, 2),
		transitionHandler:     make(map[transition]func(int)),
		advertisementTicker:   time.NewTicker(time.Minute),
		gratuitousArpTimer:    time.NewTimer(time.Minute),
		stopSignal:            make(chan struct{}),
		protectedIPaddrs:      make(map[[16]byte]*net.Interface),
	}

	transitionCh := make(chan transition, 1)
	vr.Enroll(Master2Backup, func(int) {
		transitionCh <- Master2Backup
	})

	done := startRouterLoop(vr)
	defer stopRouterLoop(t, vr, done)

	// Same priority but higher IP — tiebreaker loss
	pkt := makeAdvertPacket(100, 100, net.IPv4(192, 0, 2, 20))
	vr.packetQueue <- pkt

	expectTransition(t, transitionCh, Master2Backup, 500*time.Millisecond)
}

func TestShutdownResourcesIdempotent(t *testing.T) {
	announcer := &mockAddrAnnouncer{}
	conn := &mockIPConnection{}
	vr := &VirtualRouter{
		ipAddrAnnouncer:  announcer,
		iplayerInterface: conn,
		stopSignal:       make(chan struct{}),
		managedVMACs:     make(map[string]string),
		managedVIPs:      make(map[[16]byte]*managedVIP),
		netlinkOps:       newFakeNetlinkOps(),
	}
	vr.shutdownResources()
	vr.shutdownResources() // Second call should be no-op
	if !announcer.isClosed() {
		t.Fatal("expected announcer to be closed")
	}
	if !conn.isClosed() {
		t.Fatal("expected connection to be closed")
	}
}

func TestDrainBackupPacketsEmptyQueue(t *testing.T) {
	vr := &VirtualRouter{
		packetQueue: make(chan *VRRPPacket, 1),
	}
	if vr.drainBackupPackets(true) {
		t.Fatal("expected false for empty queue")
	}
}

func TestHandleBackupPacketPriority0ResetToSkewTime(t *testing.T) {
	vr := &VirtualRouter{
		priority:              100,
		preferredSourceIP:     net.IPv4(192, 0, 2, 10).To16(),
		advertisementInterval: 10,
		skewTime:              5,
	}
	vr.setMasterAdvInterval(10)
	vr.makeMasterDownTimer()
	defer vr.masterDownTimer.Stop()

	pkt := makeAdvertPacket(0, 10, net.IPv4(192, 0, 2, 1))
	result := vr.handleBackupPacket(pkt)
	if !result {
		t.Fatal("expected priority-0 to return true (trigger skew time)")
	}
}

func TestLookupInterfaceWithCustomFunc(t *testing.T) {
	called := false
	vr := &VirtualRouter{
		interfaceByName: func(name string) (*net.Interface, error) {
			called = true
			return &net.Interface{Name: name}, nil
		},
	}
	iface, err := vr.lookupInterface("eth0")
	if err != nil {
		t.Fatalf("lookupInterface failed: %v", err)
	}
	if !called {
		t.Fatal("expected custom interfaceByName to be called")
	}
	if iface.Name != "eth0" {
		t.Fatalf("expected eth0, got %s", iface.Name)
	}
}

func TestLookupInterfaceNilFunc(t *testing.T) {
	vr := &VirtualRouter{
		interfaceByName: nil,
	}
	// Will use net.InterfaceByName which will fail for a non-existent interface
	_, err := vr.lookupInterface("nonexistent-iface-12345")
	if err == nil {
		t.Fatal("expected error for non-existent interface")
	}
}

func TestSendEventNonBlocking(t *testing.T) {
	vr := &VirtualRouter{
		eventChannel: make(chan EVENT, 1),
		stopSignal:   make(chan struct{}),
	}
	// First send goes directly into the buffered channel
	vr.sendEvent(HEARTBEAT_UP)
	// Second send should use the goroutine fallback (non-blocking)
	vr.sendEvent(HEARTBEAT_DOWN)

	// Read first event
	event := <-vr.eventChannel
	if event != HEARTBEAT_UP {
		t.Fatalf("expected HEARTBEAT_UP, got %v", event)
	}

	// The second event should arrive via the background goroutine
	select {
	case event = <-vr.eventChannel:
		if event != HEARTBEAT_DOWN {
			t.Fatalf("expected HEARTBEAT_DOWN, got %v", event)
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatal("expected second event to be delivered")
	}
}

func TestSendEventStopSignal(t *testing.T) {
	vr := &VirtualRouter{
		eventChannel: make(chan EVENT, 1),
		stopSignal:   make(chan struct{}),
	}
	// Fill channel
	vr.eventChannel <- START
	// Send another, triggering the goroutine path
	vr.sendEvent(HEARTBEAT_UP)
	// Close stop signal to unblock the goroutine
	close(vr.stopSignal)
	// Drain the channel
	<-vr.eventChannel
	// Allow goroutine to exit
	time.Sleep(50 * time.Millisecond)
}

func TestSetThrottleInterval(t *testing.T) {
	mockClient := &mockARPClient{}
	sender := newARPInterfaceSender(mockClient, 10*time.Millisecond)
	defer sender.close()

	sender.setThrottleInterval(50 * time.Millisecond)
	if got := sender.getThrottleInterval(); got != 50*time.Millisecond {
		t.Fatalf("expected 50ms, got %v", got)
	}
}

func TestNewIPv4AddrAnnouncerAndClose(t *testing.T) {
	announcer := NewIPv4AddrAnnouncer()
	if announcer == nil {
		t.Fatal("expected non-nil announcer")
	}
	// Close an empty announcer should not error
	if err := announcer.Close(); err != nil {
		t.Fatalf("Close empty announcer failed: %v", err)
	}
}

func TestNewIPIPv6AddrAnnouncerAndClose(t *testing.T) {
	announcer := NewIPIPv6AddrAnnouncer()
	if announcer == nil {
		t.Fatal("expected non-nil announcer")
	}
	// Close an empty announcer should not error
	if err := announcer.Close(); err != nil {
		t.Fatalf("Close empty IPv6 announcer failed: %v", err)
	}
}

func TestMasterHeartbeatDownTransitionsToFault(t *testing.T) {
	conn := &recordingIPConnection{}
	announcer := &mockAddrAnnouncer{}
	vr := &VirtualRouter{
		state:                 MASTER,
		priority:              100,
		advertisementInterval: 100,
		ipvX:                  IPv4,
		preferredSourceIP:     net.IPv4(192, 0, 2, 10).To16(),
		ipAddrAnnouncer:       announcer,
		iplayerInterface:      conn,
		eventChannel:          make(chan EVENT, 2),
		packetQueue:           make(chan *VRRPPacket, 1),
		transitionHandler:     make(map[transition]func(int)),
		advertisementTicker:   time.NewTicker(time.Minute),
		gratuitousArpTimer:    time.NewTimer(time.Minute),
		stopSignal:            make(chan struct{}),
		protectedIPaddrs:      make(map[[16]byte]*net.Interface),
		heartbeatInterface:    "eth0",
	}

	transitionCh := make(chan transition, 1)
	vr.Enroll(Master2Fault, func(int) {
		transitionCh <- Master2Fault
	})

	done := startRouterLoop(vr)
	defer stopRouterLoop(t, vr, done)

	vr.eventChannel <- HEARTBEAT_DOWN
	expectTransition(t, transitionCh, Master2Fault, 500*time.Millisecond)
	if vr.state != FAULT {
		t.Fatalf("expected FAULT state, got %d", vr.state)
	}
}

func TestInitHeartbeatDownTransitionsToFault(t *testing.T) {
	announcer := &mockAddrAnnouncer{}
	conn := &mockIPConnection{}
	vr := &VirtualRouter{
		state:              INIT,
		ipAddrAnnouncer:    announcer,
		iplayerInterface:   conn,
		eventChannel:       make(chan EVENT, 2),
		packetQueue:        make(chan *VRRPPacket, 1),
		transitionHandler:  make(map[transition]func(int)),
		stopSignal:         make(chan struct{}),
		heartbeatInterface: "eth0",
		protectedIPaddrs:   make(map[[16]byte]*net.Interface),
	}

	transitionCh := make(chan transition, 1)
	vr.Enroll(Init2Fault, func(int) {
		transitionCh <- Init2Fault
	})

	done := startRouterLoop(vr)
	defer stopRouterLoop(t, vr, done)

	vr.eventChannel <- HEARTBEAT_DOWN
	expectTransition(t, transitionCh, Init2Fault, 500*time.Millisecond)
}

func TestHandleBackupPacketNoPreempt(t *testing.T) {
	vr := &VirtualRouter{
		priority:              200,
		preempt:               false,
		preferredSourceIP:     net.IPv4(192, 0, 2, 10).To16(),
		advertisementInterval: 10,
	}
	vr.setMasterAdvInterval(10)
	vr.makeMasterDownTimer()
	defer vr.masterDownTimer.Stop()

	// Lower priority but preempt is disabled, so should reset timer
	pkt := makeAdvertPacket(50, 10, net.IPv4(192, 0, 2, 1))
	result := vr.handleBackupPacket(pkt)
	if !result {
		t.Fatal("expected noPreempt to reset timer and return true")
	}
}

func TestHandleBackupPacketHigherPriorityResetsTimer(t *testing.T) {
	vr := &VirtualRouter{
		priority:              100,
		preempt:               true,
		preferredSourceIP:     net.IPv4(192, 0, 2, 10).To16(),
		advertisementInterval: 10,
	}
	vr.setMasterAdvInterval(10)
	vr.makeMasterDownTimer()
	defer vr.masterDownTimer.Stop()

	// Higher priority packet resets timer
	pkt := makeAdvertPacket(200, 10, net.IPv4(192, 0, 2, 1))
	result := vr.handleBackupPacket(pkt)
	if !result {
		t.Fatal("expected higher priority to reset timer and return true")
	}
}
