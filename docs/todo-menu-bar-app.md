# TODO: Menu Bar Status Surface for Key

## Context

`Key.app` is now the setup and dashboard surface for `Key Agent`, but there is still no lightweight always-available status entry point.

A menu bar version could make the current state easier to glance at without turning the main app into a permanently open dashboard.

## Goal

Add a small menu bar surface that shows the most important current state:

- agent available
- agent currently running or idle
- vault session warm or locked

The menu bar item should feel like a compact companion to the main dashboard, not a second full interface.

## Proposed first pass

Use a minimal `MenuBarExtra`-style surface with:

- a small status title or icon treatment
- current state summary
- `Open Key`
- `Refresh`
- copyable or visible CLI hints like `key unlock` when relevant

The first pass should remain read-only, consistent with the current dashboard direction.

## Why it fits

- quicker access than reopening the main dashboard window
- useful companion to a refresh-first app model
- good place for lightweight status without adding full live monitoring to the main app

## Relationship to dashboard live status

This should share the same state model as the main dashboard.

- initial state should come from the same snapshot collector
- if distributed notifications are added later, the menu bar surface should subscribe through the same app-level model rather than inventing a second status path

## Suggested contents

Top section:

- status summary such as `Key Agent idle` or `Vault session warm`
- short secondary line with the most useful next bit of context

Actions:

- `Open Key`
- `Refresh`

Optional read-only info:

- shell `key` path or version mismatch warning
- session expiry time when unlocked
- CLI hint when the agent is locked

## Non-goals

- do not add secret browsing or editing in the menu bar
- do not add in-menu unlock or lock controls in the first pass
- do not duplicate the full details view from the main dashboard
- do not add polling just for the menu bar

## Open questions

- whether the menu bar item should always be present or only when launched by the main app
- whether the icon should visually change for locked vs warm session state
- whether the menu bar should open the dashboard window automatically on first-run approval problems

## Implementation sketch

1. Introduce a shared app-level status model that both the dashboard window and menu bar surface can observe.
2. Add a minimal menu bar extra that renders summary state plus `Open Key` and `Refresh`.
3. Reuse the existing snapshot collector for initial and manual refresh.
4. If live distributed notifications are added later, route them through the shared model so both surfaces update together.

