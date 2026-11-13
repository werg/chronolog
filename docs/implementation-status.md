# Implementation Status

Chronolog is an unreleased prototype with one signed transaction format and
one execution path. There is no stored-data compatibility decoder or protocol
migration path. The contract is
[Specification 10](implementation-specs/10-deterministic-sql-transactions.md)
and the [design](design.md).

## End-to-end path

Implemented and covered by executable tests:

- transactions as ordered lists of ordinary SQLite statements with positional
  or named bindings over SQLite's five storage classes;
- a pinned native DoltLite engine with per-transaction fixed inputs (`'now'` =
  author timestamp, `random()` seeded from the transaction id, UTC
  `localtime`, zeroed connection counters) and native `chronolog_assert`;
- an authorizer block-list (attachments, transaction control, writing pragmas,
  temporary objects, Dolt functions and tables, `chronolog_*` writes,
  `total_changes`, `sqlite_offset`, storage-reading modules); everything else
  the engine supports is allowed, including DDL, triggers, views, generated
  columns, windows, JSON, FTS5, R-tree and sqlite-vec;
- accepted/rejected outcomes with a rejection code (`assert:<code>`,
  `constraint`, `step_limit`, `denied`, `prepare`, `binding`, `too_large`,
  `mismatch`, `error`, `manifest_mismatch`) and failing statement index,
  recorded in the replicated `chronolog_transactions` table;
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
- `transaction.submit`, outcome, settlement, local and live query RPCs; the
  TypeScript client, React hooks, CLI, daemon, examples and chaos workloads.

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

## Release gates outside this prototype

- cross-platform replay comparison (Linux/macOS) of the pinned engine build,
  plus resource characterization on release hardware;
- non-Linux/hardware-backed key providers and external security review; and
- witnessed pilot evidence for prior-version upgrade, snapshot/fork repair,
  traversal, sizing, and alerting.

The internal authorizer/protocol assessment and unresolved findings are in
[the threat review](security-threat-review.md). The ordered queue is
[`upcoming.md`](../upcoming.md).
