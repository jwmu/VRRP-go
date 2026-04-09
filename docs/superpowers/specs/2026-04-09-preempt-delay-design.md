# VRRP Delayed Preemption Design

## Goal

Add keepalived-like delayed preemption to the VRRP `BACKUP` state.

When delayed preemption is enabled, a higher-priority `BACKUP` router must not preempt a lower-priority live `MASTER` immediately. Instead, it should wait for a configured delay window and only become `MASTER` if the preemption condition remains continuously true for that entire window.

The design must preserve current behavior by default.

## Current Behavior

The current implementation only has a boolean preemption switch:

- `preempt=false`: a `BACKUP` router never preempts a live peer based on priority
- `preempt=true`: a higher-priority `BACKUP` router effectively preempts immediately by allowing the existing `Master_Down_Timer` path to complete

There is no separate time-based preemption control today.

## Desired Semantics

Delayed preemption follows these rules:

1. It applies only when the router is in `BACKUP`
2. It applies only when the peer `MASTER` is still alive and advertising
3. The delay starts when the router first receives an advertisement from a lower-priority peer that it is allowed to preempt
4. The delay remains valid only while that preemption condition stays continuously true
5. If any later advertisement breaks that condition, the delay is cancelled immediately
6. If the delay expires while the condition is still valid, the router transitions from `BACKUP` to `MASTER`
7. If the peer disappears entirely, or sends a priority-0 advertisement, the router follows the existing fast takeover behavior instead of waiting for the preemption delay

## Design

### Configuration Model

Keep the existing `preempt bool` semantics unchanged:

- `preempt=false` still disables priority-based preemption
- `preempt=true` still allows priority-based preemption

Add a new configuration field:

- `preemptDelay time.Duration`

Add a new setter:

- `SetPreemptDelay(time.Duration) *VirtualRouter`

Defaults:

- `preemptDelay=0`

With the default value, existing deployments keep the current behavior with no delay.

### Runtime State

Add two `VirtualRouter` runtime fields:

- `preemptDelayTimer *time.Timer`
- `preemptPending bool`

Responsibilities:

- `masterDownTimer` keeps its current meaning: detect that the current `MASTER` is gone
- `preemptDelayTimer` is only for delayed takeover while the current `MASTER` is still alive
- `preemptPending` records that the router is currently inside a delayed-preemption window

This keeps failure detection and delayed-preemption behavior separate.

### BACKUP Advertisement Handling

In `BACKUP`, incoming advertisements are handled as follows.

#### Case 1: Peer advertises priority 0

This is a relinquish path, not a delayed-preemption path.

Behavior:

- cancel any preemption delay state
- set `Master_Down_Timer` to `Skew_Time`
- keep the existing fast takeover behavior

#### Case 2: Peer has higher priority, or same priority with preferred tie-breaker

This means the local router must not preempt.

Behavior:

- cancel any preemption delay state
- update `advertisementIntervalOfMaster`
- reset `Master_Down_Timer`

#### Case 3: Peer has lower priority, but `preempt=false`

This means the local router is still not allowed to preempt.

Behavior:

- cancel any preemption delay state
- update `advertisementIntervalOfMaster`
- reset `Master_Down_Timer`

#### Case 4: Peer has lower priority, and `preempt=true`

This is the only path that can trigger delayed preemption.

If `preemptDelay==0`:

- preserve current behavior
- do not reset `Master_Down_Timer`
- allow the current path to promote to `MASTER` without introducing a new wait

If `preemptDelay>0`:

- if `preemptPending=false`, start `preemptDelayTimer` and set `preemptPending=true`
- if `preemptPending=true`, keep waiting and do not restart the delay
- when `preemptDelayTimer` expires, transition `BACKUP -> MASTER`

This implements the agreed behavior that the delay begins on the first lower-priority advertisement and only succeeds if the condition stays continuously true.

### Delay Cancellation Rules

The delayed-preemption window must be cleared immediately when any of the following happens:

- a later advertisement no longer satisfies the preemption condition
- the router leaves `BACKUP`
- the router shuts down
- the router enters `FAULT`
- the router receives a priority-0 advertisement and switches back to the fast takeover path

Delayed-preemption state does not survive a state transition.

### Interaction With FAULT Recovery

`FAULT` recovery must not inherit an earlier delayed-preemption window.

When the router returns from `FAULT` to `BACKUP`:

- `preemptPending` must be false
- `preemptDelayTimer` must be stopped
- a new delay window starts only after a new qualifying lower-priority advertisement is received

This keeps delayed preemption scoped to the current continuous `BACKUP` observation window.

### Timer Helpers

Add dedicated helpers similar to the existing timer utilities:

- `makePreemptDelayTimer()`
- `stopPreemptDelayTimer()`
- `clearPreemptDelay()`

`clearPreemptDelay()` should:

- stop the timer if it exists
- safely drain it if needed
- set `preemptPending=false`

The design intentionally avoids repeated timer resets during a valid delay window. The timer starts once on the first qualifying advertisement and is either cancelled or allowed to expire.

### State Transition Integration

The following transitions must clear delayed-preemption state:

- `BACKUP -> MASTER`
- `BACKUP -> FAULT`
- `BACKUP -> INIT`
- `FAULT -> BACKUP`
- shutdown from any state

Only `BACKUP` should ever observe `preemptDelayTimer.C`.

## Implementation Changes

### `vrrp/VirtualRouter.go`

- add `preemptDelay`, `preemptDelayTimer`, and `preemptPending` fields
- add `SetPreemptDelay(time.Duration) *VirtualRouter`
- add helper methods for preemption-delay timer lifecycle
- update `enterMaster`, `enterBackup`, `enterFault`, and shutdown paths to clear delayed-preemption state where needed
- update the `BACKUP` branch in `eventSelector()` to:
  - start delayed preemption on the first qualifying lower-priority advertisement
  - cancel delayed preemption when the condition breaks
  - continue using `Master_Down_Timer` for peer loss and priority-0 fast takeover
- add a `select` branch for `preemptDelayTimer.C` in `BACKUP`

### `vrrp/constants.go`

- no protocol constant changes required
- no new public state is required for this feature

## Tests

Extend `vrrp/VirtualRouter_test.go` with at least these cases:

1. `preemptDelay=0` preserves existing behavior
2. `preempt=true` and `preemptDelay>0`:
   - the first qualifying lower-priority advertisement starts delayed preemption
   - the router stays `BACKUP` before the delay expires
   - the router becomes `MASTER` after the delay expires
3. a qualifying delay is cancelled by a later higher-priority advertisement
4. a qualifying delay is cancelled by a same-priority advertisement that wins by source IP tie-break
5. a qualifying delay is cancelled by `priority=0`, and the existing fast takeover path still applies
6. `preempt=false` ignores `preemptDelay`
7. entering `FAULT` clears delayed-preemption state
8. recovery from `FAULT` does not reuse an old delayed-preemption window
9. shutdown clears delayed-preemption state without leaking timer events

## Risks And Constraints

- The existing `BACKUP` branch relies on `Master_Down_Timer` semantics that already combine peer liveness and takeover timing, so tests must pin the delayed-preemption behavior carefully
- Timer cleanup must mirror the existing defensive stop-and-drain pattern to avoid stale timer firings
- The feature must not change behavior when `preemptDelay=0`

## Non-Goals

- No keepalived configuration parser or config-file compatibility layer
- No new VRRP protocol field or wire-format change
- No refactor of the full state machine into a table-driven design
- No change to current `MASTER` or `FAULT` election semantics beyond clearing delayed-preemption runtime state when leaving `BACKUP`
