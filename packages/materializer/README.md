# `@chronolog/materializer`

Defines the deterministic execution contract shared by all Chronolog sessions, plus the SQL-free event materializer.

## Execution contract

`ChronologMaterializationRuntime` separates replay/publication from immutable snapshot reads:

- The replica passes ordered `ReplayProposal` records and verified `PeerExecutionControls`.
- Replaying produces a candidate revision; publishing exposes SQL state, events, outcomes, and revision atomically.
- Captured read views pin an exact revision and must be released when done.
- Deterministic time and entropy come exclusively from the signed transaction, never ambient clocks or RNG.

## Event materializer

`createEventMaterializationRuntime({ store, namespace })` executes event-only programs over any `BytesStore`:

- Writes immutable indexed records before advancing an atomic head pointer.
- Verifies linked history integrity on reopen and enforces bounded record count and byte limits.
- Rejects SQL steps with `profile:sql-disabled` and identifies itself with `eventExecutionManifest()`.
- On an uncertain storage write, closes mutation ports and requires reopen from the durable head while keeping existing read snapshots intact.
