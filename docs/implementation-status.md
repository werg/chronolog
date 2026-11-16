# Implementation Status

Chronolog is an unreleased prototype with one signed transaction format,
shared record/evidence storage and one SQL materializer. A signed group
configuration selects the peer or coordinated history policy. Native and
browser hosts supply their storage, engine and connection adapters. The
transaction contract is
[Specification 10](implementation-specs/10-deterministic-sql-transactions.md)
and the [design](design.md).

## End-to-end path

Implemented and covered by executable tests:

- transactions as ordered lists of steps (program version 2): ordinary SQLite
  statements with positional or named bindings over SQLite's five storage
  classes, and typed platform operations;
- a pinned DoltLite execution profile with per-transaction fixed inputs (`'now'` =
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
  `binding`, `too_large`, `mismatch`, `error`) and
  failing step index, recorded in the replicated `chronolog_transactions`
  table. Missing keys, missing records and an unavailable or incompatible
  execution manifest block application rather than becoming SQL rejections;
- empty-schema genesis, atomic rollback of rejected transactions, Dolt
  checkpoints, suffix replay, restart/reopen, and outcome changes after late
  predecessors;
- transport-neutral signed feed records and content-addressed immutable
  evidence, exact-byte durable storage, in-process peer links, native SQLite
  storage and SSB secret-handshake replication, relay through connected members,
  fork evidence and quarantine;
- replicated signed governance, durable serialized reader/writer enrollment,
  explicit historical access and HPKE epoch rotation. Built-in signed
  configurations keep validators, root, administration feed and validation
  policy fixed, with authoring guards against reconfiguration;
- peer history using validator attestations, heartbeats, watermarks and
  revision-closure evidence; its order uses author timestamp, signing key and
  stable proposal ID, independent of the outer transport sequence;
- coordinated history using a fixed authority, contiguous ordered entries and
  portable prefix certificates. Canonical position controls authorization and
  order; author timestamps cannot move late submissions into final history;
- distinct actual local/final SQL revisions, durable prefix publication and
  recovery, final accepted/rejected transaction waits, and view/revision
  metadata on ordinary and live queries;
- `transaction.submit` (SQL and platform steps), outcome, settlement, local and
  live query RPCs; the TypeScript client with typed `platformOp` builders,
  live enrollment and explicit local/final views, React hooks, CLI
  (`{"platform": …}` steps), daemon, examples and chaos
  workloads (DDL by the root administrator, mixed-author writes through
  grants, cross-owner probes, platform-trigger and owner invariants);
- fork seeding that keeps owners, teams, memberships and grants, and
  `verify-fork` comparing them.

## History, enrollment and relay acceptance

The two policies share node orchestration, protocol decoding, materialization
and durable record/evidence storage. Proposal identity comes from the canonical
transaction core, so receiving the same proposal through another author feed or
another connection cannot repeat its SQL effects. The node supplies canonical
order to the materializer instead of allowing it to sort a second time.

The [governed peer integration](../test/governed-peer.e2e.test.ts) exercises
live reader/writer enrollment and fixed-validator revision closure. The
[coordinated integration](../packages/node-core/src/coordinated-governed.integration.test.ts)
checks grant receipt before activation, readiness after certification,
revocation at canonical positions, rejection of backdated old-grant proposals,
same-key regrant, and durable reopen. Earlier final rows and outcomes stay
unchanged. A clean replica also reconstructs encrypted history from certified
ordered evidence alone: verified historical key envelopes are received before
replaying earlier SQL, without activating later membership early.

The optional [Tendriller package](../packages/transport-tendriller/README.md)
uses pinned public SDK/engine artifacts. It provides exact-envelope append
retry, retained catch-up, immutable proof storage, and an authenticated
on-demand authority endpoint that reads its own committed head. Certificates
stay outside the log they certify. Core packages do not depend on Tendriller.

Its SQL integration runs independent writers through explicit shared-collective
membership, resolves a contested task with one accepted transaction and one SQL
assertion rejection, and reconstructs the same final results on a fresh peer
while the hub is unavailable. Lost append/certificate replies, recovery of
governance publication order, authorization failures and destructive history
rollback/forks have targeted tests.

Durable operation identities cover submission and governance approval. The
public [client guide](../packages/client/README.md) distinguishes durable
publication, current speculative outcomes and final application. A receipt alone
does not establish finality; readiness exposes missing keys/history,
disconnection, incompatible engines and revocation.

## Browser implementation and qualification

The [browser runtime](../packages/runtime-browser/README.md) implements a full
peer in one dedicated Worker: OPFS-backed records, immutable evidence, private
keys and operation state; a durable control database; a real WASM DoltLite
engine; and exclusive Web Lock ownership. The page uses the ordinary
`ChronologClient` and RPC contract. Both policies and live governed enrollment
use the same core as native peers.

The WASM build compiles the pinned native engine and deterministic hooks, with
explicit storage-adapter patches and artifact provenance. Native/WASM execution
comparison tests pass for deterministic values, replay, SQL restrictions,
ownership, assertions, state/content hashes and reopening. Engine artifacts
are generated by the documented build and verified before loading.

The real Chromium Worker/OPFS acceptance run passes six checks: exclusive
storage ownership, signed/encrypted SQL through the public client, the actual
final SQL reader and native content-hash equality, durable identity and operation
recovery after graceful reopen, exact-operation recovery after Worker termination
following durable preparation, and replay after termination following candidate
SQL commit. The required browser workflow builds the artifacts and runs both
execution and browser lifecycle gates; it fails when the WASM artifact is absent.

## Daemon operational profile

The generated daemon configuration bootstraps a signed single-participant
genesis and persists its private governance material with mode `0600`. The
daemon replays and follows capability and epoch-manifest messages, uses
policy-activated capability snapshots for authorization, and decrypts retained
epochs through a live key ring. Every active reader receives new epochs;
historical epochs only through an explicit administrator rewrap. Ordinary
submission, governance and publication interruptions recover through durable
journals and replay. A lost fixed root/authority key or validator quorum still
requires a new configuration agreed out of band, usually a fork.

The native daemon remains the first pilot deployment target. Its coordinator and
publication adapter must match the direct native replay digest under
`pnpm conformance:production`; process-level publication crashes are exercised
on both sides of the atomic Dolt head move. The transport-neutral workerd/CAS
contracts remain experimental. See
[production execution](production-execution.md) for the decision and the
criteria for reconsidering workerd.

`CHRONOLOG_STATIC_MEMBERSHIP_FILE` is a testing override. Self-verifying native
distribution tooling and `chronolog doctor` are implemented. Linux pilots may set
`CHRONOLOG_SECRET_STORE=secret-service`.

Feed conflicts quarantine the feed; quarantined nodes report degraded, refuse
new publication, and expose metrics and a doctor check. Signed snapshot
archives have staged validation, atomic replacement, and signed-head fork
repair. Public SSB discovery can require an external-vantage reachability
proof and degrades health without it.

The actual abrupt-publication recovery tests pass at five points around the
durable Dolt head change. The current workspace cannot enumerate OS network
interfaces for five native socket-transport tests; that transport gate needs an
environment with the required networking facilities. Portable signed-record,
native SQL, ownership, governed-policy and publication tests remain separate
executable evidence.

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
- witnessed pilot evidence for installation, snapshot/fork repair,
  traversal, sizing, and alerting.

The internal authorizer/protocol assessment and unresolved findings are in
[the threat review](security-threat-review.md). The ordered queue is
[`upcoming.md`](../upcoming.md).
