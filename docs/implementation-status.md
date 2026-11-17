# Implementation Status

Chronolog is an unreleased prototype with one signed application history for
SQL, durable events and resident agent work. A version 3 `ChangeProgram` runs
under either the SQL/events profile or the SQL-free events profile. A signed
group configuration selects the peer or coordinated history policy; native and
browser hosts supply storage and connection adapters. The default Tendriller
composition places portable roster administration on Cloudflare, with a separate
fixed native finality signer and full application replicas. Both durable policies
use the same signed author-time ordering; inclusion receipts never order
application execution. Independent live signals require neither this history
nor its finality service. The transaction
contract is
[Specification 10](implementation-specs/10-deterministic-sql-transactions.md)
and the [design](design.md).

## End-to-end path

Implemented and covered by executable tests:

- transactions as ordered lists of steps (`ChangeProgram` version 3): ordinary
  SQLite statements with positional or named bindings over SQLite's five storage
  classes, typed platform operations and bounded literal `emit(topic, payload)`
  steps. One signed program has one atomic SQL/event outcome; event-only groups
  execute the shared event contract without loading an application SQL engine;
- a pinned DoltLite execution profile with per-transaction fixed inputs (`'now'` =
  author timestamp, `random()` seeded from the transaction id, UTC
  `localtime`, zeroed connection counters, `chronolog_actor()` = signing key),
  `recursive_triggers` on, and native `chronolog_assert`,
  `chronolog_policy_violation`, exact typed row-key/value helpers,
  `chronolog_transaction_id()` and a `RAISE(IGNORE)` lint on SQLite's own tokenizer;
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
  `TransferOffer`/`TransferAccept`/`TransferCancel` (state-bound row/dependent
  scope, or a snapshot of all current rows for a key change) and `SeedRows`
  for forks. Typed binary row keys preserve NUL and exact storage types;
  column caps compare exact values, independent of SQL collations. Row grants
  and offers do not survive delete/reinsert, rekey or ownership reuse.
  Tested against `REPLACE`, upserts,
  `INSERT … SELECT`, FK cascades, app triggers, recursion and full replay;
- **sealed data** ([guide](sealed-data.md)): signed reader-key registration,
  owner-controlled per-row reader policies with version checks, and
  client-encrypted BLOB columns with fresh AES-256-GCM keys wrapped to each
  explicit X25519/HPKE reader. Sealed writes execute ordinary row authorization
  and application triggers. Policy generations close on delete/rekey; an
  ownership transfer preserves explicit readers. The SDK checks policy
  finality before encryption by default. Old values and rejected candidates
  retain their original audiences; SQL sees public metadata and ciphertext;
- accepted/rejected outcomes with a rejection code (`assert:<code>`,
  `policy:<table>:<command>`, `platform:<reason>`, `schema_unregistered`,
  `trigger_ignore`, `constraint`, `step_limit`, `denied`, `prepare`,
  `binding`, `too_large`, `mismatch`, `error`) and
  failing step index. SQL/events groups record outcomes in the replicated
  `chronolog_transactions` table. Missing authentic payloads or locally missing
  keys for an issued epoch block application. A certified entry that contradicts
  its hash-committed metadata or names an epoch not yet issued at that position
  is deterministically invalid; it cannot stall later valid history. An
  authenticated candidate bound to another fixed execution profile receives a
  deterministic rejection. Unavailable local execution support still blocks
  application, and unauthenticated bytes never create a claimed proposal outcome.
  The unordered peer path retains pending-input semantics;
- empty-schema genesis, atomic rollback of rejected transactions, Dolt
  checkpoints, suffix replay, restart/reopen, and outcome changes after late
  predecessors;
- transport-neutral signed feed records and content-addressed immutable
  evidence, exact-byte durable storage, in-process peer links, native SQLite
  storage and SSB secret-handshake replication. The coordinated ledger retains
  small typed descriptors with inline governance and detached application
  envelopes fetched through reader-authorized peers. Persisted fork evidence
  restores quarantine on reopen and is replayed to new subscribers;
- replicated signed governance, durable serialized reader/writer enrollment,
  explicit historical access and HPKE epoch rotation. Built-in signed
  configurations keep validators, root, administration feed and validation
  policy fixed, with authoring and ingestion guards against reconfiguration
  before received membership state changes. Signed genesis names the roster
  root and initial schema administrator separately; roster authority grants no
  implicit SQL role;
- peer history using validator attestations, heartbeats, watermarks and
  revision-closure evidence; its order uses author timestamp, signing key and
  stable proposal ID, independent of the outer transport sequence;
- coordinated history using a fixed native finality signer, contiguous inclusion
  receipts and portable prefix/closed-time certificates. A fenced durable writer stores
  payloads before descriptors and commits exact-byte deduplication and head
  state before acknowledgment; certificates cover its own committed head.
  Receipt positions enumerate proofs, while signed author time, author key and
  proposal ID order application execution. Verified chronological boundaries
  activate governance. A newly included backdated proposal cannot reopen a
  closed prefix; exact retries retain their original timestamp and result;
- distinct actual local/final SQL revisions, durable prefix publication and
  recovery, final accepted/rejected transaction waits, stable final event IDs
  and bounded durable cursor reads/subscriptions. Retained views pin SQL and
  events together, and projection state/cursor pairs commit atomically;
- `change.submit`, signed publisher ingress, event publication/read/subscription,
  durable operation status, retained views, coalesced view invalidation,
  outcome/settlement and local/live
  query RPCs. The TypeScript client includes `program`, `platformOp`, enrollment,
  sealed-data helpers, projections, final-default local/final views and React hooks.
  `provisional()` exposes replaceable execution, `final()` returns either final
  outcome, and `accepted()` waits for final acceptance or throws on final rejection.
  The CLI, daemon, examples and chaos workloads exercise schema-authorized DDL,
  mixed-author writes, cross-owner probes and platform invariants;
- resident final-intent workers with durable dispatch/result journals, explicit
  uncertain-effect recovery, retained authenticated event origins and
  cancellation/deadline propagation; SQL timers
  that enforce their captured generation; and separately signed, bounded ephemeral signals that never
  advance the application log or durable cursor;
- fork seeding that keeps owners, teams, memberships and grants, and
  `verify-fork` comparing them. A database containing reader policies requires
  explicit re-encryption for a new group and is refused by automatic fork
  seeding; same-group snapshot restoration remains supported.

## History, enrollment and relay acceptance

The two policies share node orchestration, protocol decoding, materialization
and durable record/evidence storage. Proposal identity comes from the canonical
transaction core, so receiving the same proposal through another author feed or
another connection cannot repeat its SQL or effective event results. The node
supplies canonical order to the materializer instead of allowing it to sort a
second time.

The portable `MembershipAdministrator` verifies the signed cumulative control
projection and inline governance operations without receiving application descriptors. It has no application-payload
fetch port or SQL materializer. Issuing a signed revision is separate from
verifying its effective activation at a certified chronological boundary; enrollment readiness
also tracks keys, authorized connectivity and application catch-up. Host login,
roster issuance, fixed finality signing and application schema ownership remain
separate roles. The [compact control proof](membership-control-proofs.md) and
[typed ledger](typed-ledger-records.md) specify these
boundaries and unavailable-versus-invalid input handling.

The [governed peer integration](../test/governed-peer.e2e.test.ts) exercises
live reader/writer enrollment and fixed-validator revision closure. The
[coordinated integration](../packages/node-core/src/coordinated-governed.integration.test.ts)
checks grant receipt before activation, readiness after certification,
revocation at verified chronological boundaries, rejection of backdated old-grant proposals,
same-key regrant, and durable reopen. Earlier final rows and outcomes stay
unchanged. A clean replica also reconstructs encrypted history from certified
retained inclusion/closure evidence alone: verified historical key envelopes are received before
replaying earlier SQL, without activating later membership early.

The optional [Tendriller package](../packages/transport-tendriller/README.md)
uses pinned public SDK/engine artifacts. Its public application adapter maps
programs, current operation receipts, authenticated events, captured views and
view invalidations onto a native or RPC replica. The optional retained-log
adapter provides exact-envelope append
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

The [browser runtime](../packages/runtime-browser/README.md) supplies full peers
in a dedicated Worker: OPFS-backed records, detached payloads, immutable evidence,
private keys and operation state, plus exclusive Web Lock ownership. SQL/events
peers use the real WASM DoltLite engine and a durable SQL control database;
SQL-free events peers use a flushed private control journal and event execution
anchor without loading WASM or requiring cross-origin isolation. Both use the
ordinary `ChronologClient`, RPC contract and governed core.

The WASM build compiles the pinned native engine and deterministic hooks with
explicit storage-adapter patches and verified artifact provenance. The current
six-test native/WASM comparison passed locally after the upstream engine merge.
It covers replay/reopen, permissions and budgets, extension diagnostics, exact
typed row keys/value comparisons and transaction context, sealed writes and row
policy closure, and mixed SQL/event rollback with retained read views.

The real Chromium SQL/OPFS lifecycle gate contains eight checks: exclusive
storage ownership; signed/encrypted SQL through the public client; mixed
SQL/event atomicity and pinned combined reads; final SQL/native content-hash
agreement; durable identity and operation recovery after graceful reopen;
exact-operation recovery after termination following durable preparation;
persistence of a private validator cutoff absent from feed records; and replay
after termination following candidate SQL commit. Separate SQL-free, public
bridge, two-layout application and packaged Cloudflare thin-administrator gates
exercise their actual Worker/OPFS paths. The required workflow builds artifacts
and fails if the WASM artifact is absent. Historical complete passes and their
exact revisions are recorded in the [application-log evidence](plans/application-log.md);
complete quality, cross-platform, chaos and browser qualification passed for
authored head `1b5b8f26` with the final package pins. The evidence map records the
actual tested PR merge, raw reports and subsequent documentation-only checkpoint.

The combined public-adapter gate enrolls a real browser peer into a native
issuer's coordinated group, including encrypted pre-enrollment history. The two
distinct writers join an explicit collective and compete for one SQL task; native
and browser replicas agree on the final winner, assertion rejection, and database
content hash. A page reload preserves the exact claim identity. A fresh approved
browser reader then receives records, keys and certificates through an ordinary
peer link while the hub is offline, with zero hub or authority requests.

## Daemon operational profile

The default Tendriller composition keeps the roster root in Cloudflare and
runs the fixed finality signer with its persistent volume on the native host.
Signed genesis separately names the initial application schema administrator;
worker signers receive explicit program rights. A standalone self-governed
native configuration is also available.
The daemon follows capability and epoch manifests, uses policy-activated
snapshots for authorization and decrypts retained epochs through its live key
ring. Every active reader receives new epochs; historical epochs require an
explicit administrator rewrap. Durable journals preserve exact submission and
governance retries after interruption. Loss of a fixed root/authority key or
validator quorum requires a configuration agreed out of band, usually a fork.

The native daemon remains the first pilot deployment target. Its coordinator and
publication adapter must match the direct native replay digest under
`pnpm conformance:production`; process-level publication crashes are exercised
on both sides of the atomic Dolt head move. The transport-neutral workerd/CAS
application-execution contracts remain experimental; the default portable Cloudflare roster provider
does not execute application SQL. See
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

The abrupt-publication recovery gate exercises five points around the durable
Dolt head change. Native SSB socket replication, relay, restart health and durable
fork replay are required CI checks in an environment with the necessary network
facilities. Earlier complete remote runs are recorded in the application-log
evidence; a restricted local workspace does not waive that gate for a new head.
Portable records, native SQL, governed policy and publication recovery retain
their independent executable tests.

The previously outstanding mixed-author owner-row chaos rerun completed in the
recorded remote qualification. Chaos and Linux/macOS replay comparison remain
required for the final merged runtime. Owner-row CPU, storage and wider workload
costs remain part of release-hardware characterization; the
[owner-row design](design-owner-rows.md) records the earlier benchmark scope.

## Release gates outside this prototype

- cross-platform replay comparison (Linux/macOS) of the pinned engine build,
  plus resource characterization on release hardware;
- non-Linux/hardware-backed key providers and external security review; and
- witnessed pilot evidence for installation, snapshot/fork repair,
  traversal, sizing, and alerting.

The internal authorizer/protocol assessment and unresolved findings are in
[the threat review](security-threat-review.md). The ordered queue is
[`upcoming.md`](../upcoming.md).
