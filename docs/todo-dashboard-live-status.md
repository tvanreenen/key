# TODO: Dashboard Live Status via Distributed Notifications

## Context

`Key.app` currently treats dashboard state as a snapshot:

- refresh on open
- manual `Refresh` for subsequent checks
- no background polling

That keeps the app simple and avoids polling overhead, but it means the dashboard does not update immediately when `Key Agent` changes state while the window is already open.

## Goal

Improve the `Agent Process` and `Vault Session` cards so they feel more live while `Key.app` is open, without adding a polling loop or a more complex XPC subscription system.

## Proposed approach

Use `DistributedNotificationCenter` as an in-session hint channel only.

- `Key.app` still performs an authoritative snapshot on open.
- While the dashboard window is open, `Key.app` listens for distributed notifications from `Key Agent`.
- On each notification, `Key.app` refreshes the relevant dashboard state.
- If the app misses notifications while closed, the next app open re-syncs from the normal snapshot path.

This keeps notifications advisory rather than authoritative.

## Events to emit from `Key Agent`

Suggested notification names:

- `work.tvr.key.agent.didStart`
- `work.tvr.key.agent.didUnlock`
- `work.tvr.key.agent.didLock`
- `work.tvr.key.agent.willExit`

Possible payload:

- `isUnlocked`
- `sessionExpiresAt`
- `inactivityTimeoutSeconds`

The payload can be lightweight. The app should still be able to fall back to the existing `.status` XPC request if needed.

## App behavior

When `Key.app` is open:

- subscribe to the distributed notifications above
- on `didStart` or `willExit`, refresh `Agent Process`
- on `didUnlock` or `didLock`, refresh `Vault Session`
- if a notification includes enough session data, update the dashboard model directly
- otherwise trigger the existing snapshot refresh path

When `Key.app` opens:

- do the normal snapshot load first
- only then attach the live-notification observers

## Why this approach

- no polling tax
- less plumbing than a push-style XPC subscription channel
- fits the current refresh-first dashboard model
- good enough for “window is open right now” freshness

## Known limits

- distributed notifications are not durable state
- notifications can be missed if the app is closed or not listening yet
- the startup snapshot must remain the source of truth
- this should not replace the existing `.status` request

## Non-goals

- do not turn `Key.app` into a continuously authoritative monitoring tool
- do not persist any session state to disk
- do not add a background polling timer
- do not replace the current XPC status endpoint

## Implementation sketch

1. Add a small notification helper in `KeyCore` with typed event names and payload keys.
2. Post notifications from `Key Agent` on startup, unlock, lock, and shutdown.
3. Add a lightweight observer in `Key.app` that is active only while the dashboard is alive.
4. On receipt, update the model or trigger a refresh depending on the event payload.
5. Keep manual `Refresh` and initial snapshot load as-is.

