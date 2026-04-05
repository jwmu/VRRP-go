# VRRP FAULT State Design

## Goal

Add a formal `FAULT` state to the VRRP state machine.

When the heartbeat interface goes down, the router must enter `FAULT`.
While in `FAULT`, the router must not send or receive `AdvertMessage`.
When `heartbeatDownMaster=true`, the router may still take over protected VIPs while remaining in `FAULT`.
When the heartbeat interface comes back up, the router returns to the existing startup decision path: owner routers become `MASTER`, non-owner routers become `BACKUP`.

## Current Problem

The current implementation mixes two separate concerns:

1. VRRP control-plane participation
2. Ownership of protected VIPs

Today, `heartbeatDownMaster=true` reuses the `MASTER` state to keep VIP ownership during heartbeat failure. That also inherits normal `MASTER` behavior, including sending advertisements and reacting to peer advertisements. This conflicts with the required behavior for heartbeat failure isolation.

## Design

### State Model

Add a new state constant:

- `FAULT`

`FAULT` is a control-plane isolation state. It means the router is not participating in VRRP advertisement exchange, regardless of whether it currently owns the VIPs.

Add a dedicated runtime flag:

- `faultOwnsVIPs bool`

This flag records whether the router should keep or acquire VIP ownership while in `FAULT`.

The state and the flag have separate meanings:

- `state == FAULT` controls VRRP protocol behavior
- `faultOwnsVIPs == true` controls whether VIPs are active during heartbeat isolation

### Entering FAULT

Any `HEARTBEAT_DOWN` event from `INIT`, `BACKUP`, or `MASTER` moves the router into `FAULT`.

Entering `FAULT` performs the following steps:

1. Stop `advertisementTicker`, `masterDownTimer`, and `gratuitousArpTimer`
2. Decide whether VIPs should be active during fault:
   - `heartbeatDownMaster=false`: deactivate VIPs and set `faultOwnsVIPs=false`
   - `heartbeatDownMaster=true`: activate or keep VIPs active and set `faultOwnsVIPs=true`
3. Do not send any VRRP advertisement during this transition, including priority-0 advertisements
4. Set `state = FAULT`

If the router was already `MASTER`, its VIPs stay active only when `heartbeatDownMaster=true`.
If it was `INIT` or `BACKUP` and `heartbeatDownMaster=true`, it activates VIPs as part of entering `FAULT`.

### Behavior While in FAULT

`FAULT` only handles:

- `HEARTBEAT_UP`
- `SHUTDOWN`

`FAULT` ignores:

- `packetQueue` advertisements
- advertisement timer activity
- master-down timer activity

As a result, no `AdvertMessage` is sent or processed while in `FAULT`.

If `faultOwnsVIPs=true`, the router continues holding VIPs and may still announce them at fault entry using the existing address announcer path. This is not a VRRP advertisement and is allowed.

### Recovery From FAULT

On `HEARTBEAT_UP` while in `FAULT`:

1. Clear `faultOwnsVIPs`
2. Re-enter the existing startup decision logic
3. Owner routers go to `MASTER`
4. Non-owner routers go to `BACKUP`

Recovery does not attempt to restore the exact pre-fault state. It intentionally re-evaluates using the same logic as startup.

### Shutdown Semantics

If `SHUTDOWN` occurs while in `FAULT`:

1. Deactivate VIPs
2. Close protocol resources
3. Transition to `INIT`

No priority-0 advertisement is sent from `FAULT`.

## Implementation Changes

### `vrrp/constants.go`

- Add `FAULT` to the state constants
- Add new transition constants and string mappings only if transition callbacks are needed for fault entry or exit

### `vrrp/VirtualRouter.go`

- Add `faultOwnsVIPs` to `VirtualRouter`
- Replace the current heartbeat override logic with explicit FAULT entry and exit helpers
- Introduce an `enterFault(from int)` helper
- Update `recoverFromHeartbeatDown()` to restore normal operation from `FAULT`
- Add a `FAULT` branch to `eventSelector()`
- Guard `sendAdvertMessage()` so it returns immediately when `state == FAULT`
- Ensure no path into `FAULT` emits priority-0 VRRP advertisements

### Tests

Update and extend `vrrp/VirtualRouter_test.go`:

- Existing heartbeat-down tests should expect `FAULT`, not `BACKUP` or `MASTER`
- When `heartbeatDownMaster=false`, entering `FAULT` deactivates VIP ownership
- When `heartbeatDownMaster=true`, entering `FAULT` keeps or acquires VIP ownership without leaving `FAULT`
- `FAULT` ignores incoming advertisements
- `FAULT` never sends advertisements, including after timer-related events that would matter in normal states
- `HEARTBEAT_UP` from `FAULT` returns to the normal owner/non-owner startup path

## Risks And Constraints

- Existing code uses `MASTER` as both protocol and ownership state, so tests must pin the new separation carefully
- If any helper assumes "VIP active implies MASTER", that assumption must be removed or localized
- `FAULT` should stop timers before state change side effects to avoid races with advertisement sends

## Non-Goals

- No full state-machine table refactor
- No change to normal `MASTER` and `BACKUP` election semantics outside heartbeat fault handling
- No change to VRRP packet encoding or network transport behavior outside the new FAULT guards
