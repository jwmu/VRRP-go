# FAULT State Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a formal `FAULT` state that is entered on heartbeat interface failure, blocks VRRP advertisement send/receive while active, and optionally keeps VIP ownership when `heartbeatDownMaster=true`.

**Architecture:** Extend the existing `VirtualRouter` state machine with an explicit `FAULT` branch and a separate `faultOwnsVIPs` flag so control-plane participation and VIP ownership are no longer conflated. Update heartbeat transitions to funnel through dedicated FAULT entry and recovery helpers, then lock the behavior down with focused `VirtualRouter` tests that fail before implementation.

**Tech Stack:** Go, standard library timers/channels, existing `vrrp/VirtualRouter.go` state machine tests in `go test`

---

### Task 1: Lock In FAULT Expectations With Failing Tests

**Files:**
- Modify: `vrrp/VirtualRouter_test.go`
- Modify: `vrrp/constants.go`
- Test: `vrrp/VirtualRouter_test.go`

- [ ] **Step 1: Write the failing tests for heartbeat-down and fault isolation**

```go
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
		transitionHandler:     make(map[transition]func()),
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
		transitionHandler:     make(map[transition]func()),
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
```

- [ ] **Step 2: Run the focused tests and verify they fail**

Run: `go test ./vrrp -run 'TestHeartbeatDownTransitionsToFaultAndRecoveryReturnsToBackupForNonOwner|TestHeartbeatDownWithMasterOverrideStaysInFaultAndOwnsVIPs'`

Expected: compile or assertion failure because `FAULT` and `faultOwnsVIPs` do not exist yet, or heartbeat-down still transitions into `BACKUP`/`MASTER`

- [ ] **Step 3: Add the failing tests for no AdvertMessage send/receive in FAULT**

```go
type recordingIPConnection struct {
	mockIPConnection
	writes int
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
		transitionHandler:     make(map[transition]func()),
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
```

- [ ] **Step 4: Run the focused fault-isolation tests and verify they fail**

Run: `go test ./vrrp -run 'TestSendAdvertMessageSkipsFaultState|TestFaultStateIgnoresIncomingAdvertisements'`

Expected: compile failure because `FAULT` is undefined, or runtime failure because `sendAdvertMessage` still writes and `eventSelector` has no `FAULT` branch

- [ ] **Step 5: Commit the red tests**

```bash
git add vrrp/VirtualRouter_test.go vrrp/constants.go
git commit -m "test: define FAULT heartbeat behavior"
```

### Task 2: Implement Explicit FAULT State And Recovery

**Files:**
- Modify: `vrrp/constants.go`
- Modify: `vrrp/VirtualRouter.go`
- Test: `vrrp/VirtualRouter_test.go`

- [ ] **Step 1: Add the state and router fields required by the tests**

```go
const (
	INIT = iota
	MASTER
	BACKUP
	FAULT
)

type VirtualRouter struct {
	// ...
	heartbeatDownMaster bool
	faultOwnsVIPs       bool
	// ...
}
```

- [ ] **Step 2: Implement minimal FAULT entry and recovery helpers**

```go
func (r *VirtualRouter) enterFault(from int) {
	r.stopStateTimers()
	r.faultOwnsVIPs = r.heartbeatDownMaster
	if r.faultOwnsVIPs {
		if err := r.activateManagedVIPs(); err != nil {
			logger.GLoger.Printf(logger.ERROR, "VirtualRouter.activateManagedVIPs: %v", err)
		}
		if err := r.ipAddrAnnouncer.AnnounceAll(r); err != nil {
			logger.GLoger.Printf(logger.ERROR, "VirtualRouter.enterFault: %v", err)
		}
	} else {
		if err := r.deactivateManagedVIPs(); err != nil {
			logger.GLoger.Printf(logger.ERROR, "VirtualRouter.deactivateManagedVIPs: %v", err)
		}
	}
	r.state = FAULT
}

func (r *VirtualRouter) recoverFromHeartbeatDown() {
	if r.state != FAULT {
		return
	}
	r.faultOwnsVIPs = false
	r.enterOperationalState(Init2Master, Init2Backup)
}
```

- [ ] **Step 3: Wire `eventSelector()` to use `FAULT` instead of the old heartbeat override path**

```go
case INIT:
	select {
	case event := <-r.eventChannel:
		if event == HEARTBEAT_DOWN {
			r.enterFault(INIT)
			continue
		}
		if event == START {
			if !r.isHeartbeatUp() {
				r.enterFault(INIT)
				continue
			}
			r.enterOperationalState(Init2Master, Init2Backup)
		}
	}

case MASTER:
	select {
	case event := <-r.eventChannel:
		if event == HEARTBEAT_DOWN {
			r.enterFault(MASTER)
			continue
		}
		if event == HEARTBEAT_UP {
			r.recoverFromHeartbeatDown()
			continue
		}
	}

case BACKUP:
	select {
	case event := <-r.eventChannel:
		if event == HEARTBEAT_DOWN {
			r.enterFault(BACKUP)
			continue
		}
	}

case FAULT:
	select {
	case event := <-r.eventChannel:
		if event == HEARTBEAT_UP {
			r.recoverFromHeartbeatDown()
			continue
		}
		if event == SHUTDOWN {
			r.shutdownResources()
			r.state = INIT
			return
		}
	case <-r.packetQueue:
		continue
	}
```

- [ ] **Step 4: Run the focused tests and verify they pass**

Run: `go test ./vrrp -run 'TestHeartbeatDownTransitionsToFaultAndRecoveryReturnsToBackupForNonOwner|TestHeartbeatDownWithMasterOverrideStaysInFaultAndOwnsVIPs|TestSendAdvertMessageSkipsFaultState|TestFaultStateIgnoresIncomingAdvertisements'`

Expected: PASS

- [ ] **Step 5: Commit the minimal green state-machine change**

```bash
git add vrrp/constants.go vrrp/VirtualRouter.go vrrp/VirtualRouter_test.go
git commit -m "feat: add FAULT heartbeat state"
```

### Task 3: Close Remaining Advert And Shutdown Gaps

**Files:**
- Modify: `vrrp/VirtualRouter.go`
- Modify: `vrrp/VirtualRouter_test.go`
- Test: `vrrp/VirtualRouter_test.go`

- [ ] **Step 1: Add a failing regression test for shutdown from FAULT**

```go
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
```

- [ ] **Step 2: Run the shutdown regression test and verify it fails if shutdown still leaks adverts**

Run: `go test ./vrrp -run TestFaultShutdownDoesNotSendPriorityZeroAdvertisement`

Expected: FAIL if any FAULT shutdown path still writes advertisements, or PASS immediately if the prior implementation already satisfies the requirement

- [ ] **Step 3: Tighten `sendAdvertMessage()` and the FAULT shutdown path**

```go
func (r *VirtualRouter) sendAdvertMessage() {
	if r.state == FAULT {
		return
	}
	// existing write logic
}

case FAULT:
	select {
	case event := <-r.eventChannel:
		if event == SHUTDOWN {
			if err := r.deactivateManagedVIPs(); err != nil {
				logger.GLoger.Printf(logger.ERROR, "VirtualRouter.deactivateManagedVIPs: %v", err)
			}
			r.faultOwnsVIPs = false
			r.shutdownResources()
			r.state = INIT
			return
		}
	}
```

- [ ] **Step 4: Run the full `vrrp` test package**

Run: `go test ./vrrp`

Expected: PASS

- [ ] **Step 5: Commit the regression hardening**

```bash
git add vrrp/VirtualRouter.go vrrp/VirtualRouter_test.go
git commit -m "test: block adverts while faulted"
```

### Task 4: Final Verification And Cleanup

**Files:**
- Modify: `vrrp/VirtualRouter.go`
- Modify: `vrrp/VirtualRouter_test.go`
- Test: `vrrp/VirtualRouter_test.go`

- [ ] **Step 1: Remove dead heartbeat-override branches that FAULT made obsolete**

```go
func (r *VirtualRouter) recoverFromHeartbeatDown() {
	if r.state != FAULT {
		return
	}
	r.faultOwnsVIPs = false
	r.enterOperationalState(Init2Master, Init2Backup)
}
```

- [ ] **Step 2: Run the package tests again after cleanup**

Run: `go test ./vrrp`

Expected: PASS

- [ ] **Step 3: Inspect the diff for accidental behavior changes outside heartbeat fault handling**

Run: `git diff -- vrrp/constants.go vrrp/VirtualRouter.go vrrp/VirtualRouter_test.go`

Expected: only FAULT state, helper, event loop, and targeted test updates

- [ ] **Step 4: Commit the cleanup if needed**

```bash
git add vrrp/constants.go vrrp/VirtualRouter.go vrrp/VirtualRouter_test.go
git commit -m "refactor: simplify heartbeat fault handling"
```

- [ ] **Step 5: Prepare completion notes with test evidence**

```text
Summary:
- Heartbeat down now enters FAULT from INIT/BACKUP/MASTER
- FAULT suppresses all VRRP advertisement send/receive
- heartbeatDownMaster only controls VIP ownership while faulted
- HEARTBEAT_UP re-enters normal owner/non-owner startup logic

Verification:
- go test ./vrrp
```
