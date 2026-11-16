# Application log follow-up

The 16 November 2026 follow-up extends portable-peer-core with one signed
application history for SQL, events and resident agent work. The preferred
coordinated deployment runs its fixed authority on durable native agent storage.
Tendriller's retained Cloudflare log remains an optional adapter. Both projects
are pre-release: change APIs/protocols directly, without compatibility aliases,
legacy import, dual queues or automatic authority/policy failover.

## Work and current checkpoints

This document is a recovery map for incremental commits. A committed component
is not a claim that the entire integration or qualification gate has passed.

- [x] Replace SQL-only programs with version 3 change programs and bounded,
      canonical literal events; bind operation identity in signed transaction v2.
- [x] Add event-only execution anchored to an atomic durable record, with no SQL
      engine import; reject SQL in that fixed execution profile.
- [x] Derive effective events only from applied accepted outcomes, with whole
      proposal batches, scan progress, filter/history-bound continuations and
      pull-based delivery.
- [x] Add pinned native SQL/event read handles and authored-operation lookup.
- [x] Extend signed writer grants with independent SQL/topic/signal rights and
      explicit forwarding permission.
- [ ] Qualify mixed SQL/event rollback, exact retries, event-only restart,
      checkpoints, pinned views, rebase and scoped grants.
- [ ] Finish transport-independent limited-publisher submission and enrollment.
- [ ] Finish SQL-free browser OPFS/control persistence and browser qualification.
- [ ] Integrate fixed native authority, resident final-intent workers, timers,
      bounded peer framing and signed ephemeral signals into the daemon.
- [ ] Extend public RPC/client event, operation and coherent-view APIs and add
      pure application projections with atomic durable checkpoints.
- [ ] Exercise the public Tendriller application backend and peer connection
      boundary; refresh pinned public artifacts from the paired PR.
- [ ] Run the contrib task-board/chat pilot against the real public implementation.
- [ ] Run native quality/conformance, actual browser and failure/recovery gates.
- [ ] Update acceptance evidence and linked contrib qualification issues.

## Acceptance boundaries

Event identity is proposal plus ordinal. A rejected mixed program exposes no
SQL mutation or effective event. Missing bytes, keys, engine or I/O progress
block application; ordering evidence does not prove SQL success. Cursor scan
progress includes nonmatching and resolved rejected/no-op history, and never
passes unresolved input. Processed cursor and projection state commit together.

A fixed authority commits entry, exact-byte deduplication and rolling head before
acknowledgment, certifies its own committed head, and exports portable evidence.
It has one fenced durable owner. Authority loss pauses new finality while local
reads and certified peer catch-up continue. Old backups cannot silently reuse
acknowledged positions. Topic filtering is not confidentiality.

External effects run only after final intent. Durable dispatch identity and
provider idempotency/reconciliation are explicit; unknown external outcomes
remain uncertain. Model activity never controls persistence/sync/timer loops.
The host selects one backend and one proposal outbox for each application.

## Qualification requiring a deployment

Actual home/mobile/corporate network routing, suspended-browser behavior on the
selected device fleet, direct versus relayed byte measurements, durable-volume
loss recovery and workload cost comparison must produce real evidence. The
implementation must include reproducible harnesses and issue these remaining
measurements without inventing results. Compaction, automatic failover, dynamic
validators, full meshes, per-topic consensus and arbitrary-code consensus remain
outside this first scope.
