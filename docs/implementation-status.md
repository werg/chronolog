# Implementation Status

Chronolog is an unreleased prototype with one signed transaction format and
one execution path. There is no stored-data compatibility decoder or protocol
migration path. The contract is
[Specification 10](implementation-specs/10-deterministic-sql-transactions.md)
and the [design](design.md).

## End-to-end path

Implemented and covered by executable tests:

- transactions as ordered lists of steps (program version 2): ordinary SQLite
  statements with positional or named bindings over SQLite's five storage
  classes, and typed platform operations;
- a pinned native DoltLite engine with per-transaction fixed inputs (`'now'` =
  author timestamp, `random()` seeded from the transaction id, UTC
  `localtime`, zeroed connection counters, `chronolog_actor()` = signing key),
  `recursive_triggers` on, and native `chronolog_assert`,
  `chronolog_policy_violation` and a `RAISE(IGNORE)` lint on SQLite's own
  tokenizer;
- an authorizer block-list (attachments, transaction control, writing pragmas,
  temporary objects, Dolt functions and tables, `chronolog_*` writes and
  objects, the policy function outside platform triggers, `total_changes`,
  `sqlite_offset`, storage-reading modules), with DDL limited to admins of the
  `group` collective; everything else the engine supports is allowed,
  including triggers, views, generated columns, windows, JSON, FTS5, R-tree
  and sqlite-vec;
- **owner-controlled rows** ([design](design-owner-rows.md)): registered
  tables with a `chronolog_owner` column stamped from the signer, generated
  insert/update/delete triggers, lookup views, schema reconciliation
  (unregistered tables, foreign `chronolog_*` objects, cross-owner FK
  cascades, `RAISE(IGNORE)`), automatic table registration, and the platform operations
  `Grant`/`RevokeGrant` (row scope, column caps), `team` collectives
  (`CreateCollective`, `AcceptMembership`, `Leave`, `SetMembers`),
  `TransferOffer`/`TransferAccept` (row with dependents, or every row for a key
  change) and `SeedRows` for forks. Tested against `REPLACE`, upserts,
  `INSERT … SELECT`, FK cascades, app triggers, recursion and full replay;
- accepted/rejected outcomes with a rejection code (`assert:<code>`,
  `policy:<table>:<command>`, `platform:<reason>`, `schema_unregistered`,
  `trigger_ignore`, `constraint`, `step_limit`, `denied`, `prepare`,
  `binding`, `too_large`, `mismatch`, `error`, `manifest_mismatch`) and
  failing step index, recorded in the replicated `chronolog_transactions`
  table;
- empty-schema genesis, atomic rollback of rejected transactions, Dolt
  checkpoints, suffix replay, restart/reopen, and outcome changes after late
  predecessors;
- signed hash-chained feeds in one SQLite file per node, pull replication over
  the SSB secret handshake, relay through any connected member, fork evidence
  and quarantine;
- replicated signed governance: capability grants/revocations, validator
  changes with a monotonic timestamp floor, HPKE epoch rotation, explicit
  historical access, joining and forking groups;
- validator attestation and heartbeats, deterministic ordering, settlement
  evidence and watermarks;
- `transaction.submit` (SQL and platform steps), outcome, settlement, local and
  live query RPCs; the TypeScript client with typed `platformOp` builders,
  React hooks, CLI (`{"platform": …}` steps), daemon, examples and chaos
  workloads (DDL by the root administrator, mixed-author writes through
  grants, cross-owner probes, platform-trigger and owner invariants);
- fork seeding that keeps owners, teams, memberships and grants, and
  `verify-fork` comparing them.

## Daemon operational profile

The generated daemon configuration bootstraps a signed single-participant
genesis and persists its private governance material with mode `0600`. The
daemon replays and follows capability and epoch-manifest messages, uses
revisioned capability snapshots for authorization, and decrypts retained
epochs through a live key ring. Every active reader receives new epochs;
historical epochs only through an explicit administrator rewrap. There is no
in-protocol recovery: a lost root key or validator quorum is handled by
forking the group or out of band.

The first pilot deployment target is the native daemon. Its coordinator and
publication adapter must match the direct native replay digest under
`pnpm conformance:production`; process-level publication crashes are exercised
on both sides of the atomic Dolt head move. The transport-neutral workerd/CAS
contracts remain experimental. See
[production execution](production-execution.md) for the decision and the
criteria for reconsidering workerd.

`CHRONOLOG_STATIC_MEMBERSHIP_FILE` is a testing override. Self-verifying native
distributions and `chronolog doctor` have shipped. Linux pilots may set
`CHRONOLOG_SECRET_STORE=secret-service`.

Feed conflicts quarantine the feed; quarantined nodes report degraded, refuse
new publication, and expose metrics and a doctor check. Signed snapshot
archives have staged validation, atomic replacement, and signed-head fork
repair. Public SSB discovery can require an external-vantage reachability
proof and degrades health without it.

## Owner-rows work still open

- The mixed-author chaos run (Step 9) is to be rerun: the last run found two
  feed-transport bugs (shutdown hanging on open peers, a sticky stream error
  keeping a node degraded after a peer restart), both fixed since.
- The Step 8 benchmark is within the 10% budget end to end; the materializer
  CPU overhead left is the 32-byte owner per row (design-owner-rows Step 8).

## Release gates outside this prototype

- cross-platform replay comparison (Linux/macOS) of the pinned engine build,
  plus resource characterization on release hardware;
- non-Linux/hardware-backed key providers and external security review; and
- witnessed pilot evidence for prior-version upgrade, snapshot/fork repair,
  traversal, sizing, and alerting.

The internal authorizer/protocol assessment and unresolved findings are in
[the threat review](security-threat-review.md). The ordered queue is
[`upcoming.md`](../upcoming.md).
