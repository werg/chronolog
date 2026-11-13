# Chronolog Design

Status: current design of the unreleased prototype. The transaction contract
is [Specification 10](implementation-specs/10-deterministic-sql-transactions.md);
membership details are in [governance.md](governance.md); row ownership is in
[design-owner-rows.md](design-owner-rows.md).

## 1. What Chronolog is

Chronolog is a permissioned, peer-to-peer SQL database. Members write
**ordinary SQLite transactions**; every replica derives the same database by
executing all admitted transactions in one fixed order. Writes work offline
and replicate later. When a transaction arrives late, every replica rewinds to
a checkpoint and replays from the point where it belongs, so the result is the
same no matter in which order records arrived.

The replicated source of truth is the set of admitted transactions. The
database is derived state.

## 2. Moving parts

```text
author ──signed transaction──▶ feed ──replication──▶ every node
validators ──attestations, heartbeats──▶ feeds
node: admit (enough attestations) → order → execute on DoltLite → publish revision
clients: submit transactions, read the published revision with local SQL
```

| Piece | Package |
| --- | --- |
| Signed messages, transaction and value codecs, execution manifest | `protocol`, `canonical`, `crypto` |
| Membership: genesis, capability revisions, validation policy | `capabilities` |
| Feeds: SQLite signed-feed store and replication | `transport-ssb` |
| Node: ingest, admission, attestation, ordering, settlement | `node-core`, `control-store` |
| Deterministic execution on DoltLite | `materializer-doltlite`, `materializer` |
| Client API, RPC, React hooks, CLI, daemon | `client`, `rpc`, `react`, `apps/*` |
| Experimental workerd execution path | `runtime-workerd` ([plan](workerd-reconstruction-plan.md)) |

## 3. Transactions

A transaction candidate is signed by its author and carries:

- the group, membership revision and validation policy it was written for;
- `author_timestamp_ms`, fixed by the author;
- the execution manifest digest (engine build, platform code and limits);
- a program: an ordered list of steps, each a SQLite statement with bindings
  or a typed platform operation (grant, collective,
  transfer).

Values are SQLite's own storage classes (NULL, INTEGER, REAL, TEXT, BLOB).
DDL and DML travel in the same stream. There is no schema manifest, dialect
or migration system: the schema is whatever the accepted transactions created.
Only schema administrators (admins of the `group` collective, starting with
the root administrator) may run DDL.

A transaction that depends on earlier state says so in SQL, usually with
`chronolog_assert(condition, 'code')`. If any statement fails, the transaction
is **rejected** and has no effect; otherwise it is **accepted**. Only the
outcome (and a rejection code and step index) is recorded. Values
returned by statements are not replicated.

## 3a. Owner-controlled rows

Every application table is put under owner checks when it is created (no
extra step) and has a `chronolog_owner` column,
stamped with the signer of the transaction that inserted the row (stored as
a small integer id; `chronolog_principals` maps ids to keys).
Platform-generated triggers, enforced by the pinned engine on every replica,
let only the owner, a collective the signer belongs to, or a key the owner
granted access insert, update or delete a row. The root administrator and
schema administrators are ordinary actors under these checks: they cannot
widen anyone's rights, but they may narrow them with ordinary app triggers,
whose writes are themselves checked as the signer. Any violation aborts the
whole transaction (`policy:<table>:<command>`); rows are never skipped.
Ownership moves only by an offer accepted by the recipient; a planned key
change is a bulk transfer. Reads are not restricted: every reader node holds
every row. See [design-owner-rows.md](design-owner-rows.md).

## 4. Determinism

Every replica runs the same pinned DoltLite engine build on the same state in
the same order. The engine inputs that do not come from SQL are fixed per
transaction: `'now'` is the author timestamp, `random()` is seeded from the
transaction id, `localtime` is UTC, connection counters start at zero, and
`chronolog_actor()` is the signing key. Platform operations are trusted
TypeScript whose digest is part of the execution manifest. A
short block-list (attachments, transaction control, writing pragmas, temporary
objects, Dolt functions, Chronolog's own tables, storage-dependent functions)
is enforced by SQLite's authorizer. Everything else SQLite supports is
allowed. Replicas' state digests can be compared (snapshots and the chaos
harness do), so a missed case is detectable rather than silent.

## 5. Admission and order

Validators are members holding the validator role. A validator attests a
candidate if its author may write and its author timestamp is above the
validator's **acceptance cutoff**: a durable, monotonic bound that trails the
validator's clock by the group's `cutoff_lag_ms`. A candidate is **admitted**
once the attestations a replica sees satisfy the pinned validation policy
(at least N distinct validators). Admission is monotonic.

Admitted transactions are ordered by the immutable key

```text
(author_timestamp_ms, author_id, author_feed_sequence, tx_id)
```

Validators never choose the position; more attestations never move it. A
transaction that becomes visible late sorts into its fixed position and the
suffix after it is replayed.

Validators publish **heartbeats** with their current cutoff. Once the feeds
of a blocking set of validators are replicated past heartbeats whose cutoffs
exceed time T, no new transaction can be admitted at or before T: everything
before T is settled. New validators inherit a floor at least as high as the
group's (`validatorFloorMs` never decreases), so admitting a validator cannot
reopen settled history.

## 6. Replication

Each node has one **feed**: an append-only, hash-chained log of signed
records (candidates, attestations, heartbeats, governance messages). Feeds are
stored in one SQLite file per node. A record is appended only if it is the
next one of its feed, so feeds have no gaps; a second record at an existing
sequence is kept as fork evidence and quarantines that feed.

Nodes connect with Secure Scuttlebutt's authenticated secret handshake. On
each connection a node asks the peer for every feed it wants, after its local
head, and keeps the stream open for new records. A node wants its own feed,
its configured peers' feeds, the administration feed and the feed of every
granted member, so records relay through any connected member. There is no
record size limit beyond a configurable maximum (64 MiB by default).

## 7. Membership and encryption

A group starts from a signed **genesis**; the root administrator then
publishes signed **capability revisions** on the administration feed. Roles:
writer, validator, reader, administrator. Revocation is prospective: it stops
new signatures, it does not erase history.

Records are encrypted with per-epoch keys. The administrator rotates epochs
and wraps each epoch key to every reader's HPKE key; historical epochs are
given to a reader only by an explicit administrator action.

## 8. Materialization

The node executes transactions on DoltLite. Each published revision is a
Dolt commit (`chronolog_head`, `chronolog_rev_*`); checkpoints
(`chronolog_cp_*`) are kept every N transactions so a late arrival replays
only from the nearest checkpoint. Readers run local SQL against an immutable
published revision and may subscribe to live query results. The replicated
log of outcomes is the table `chronolog_transactions`, readable by
transactions.

## 9. Failure handling

There is no in-protocol recovery. A node whose state is suspect restores from
a verified snapshot or replays from feeds. If the root key is lost, the
validator set can no longer meet its policy, or settled history must change,
participants coordinate out of band and **fork**: a new group whose genesis
names its origin and is seeded by its root administrator, keeping every row's
owner ([governance.md](governance.md#forking-a-group)).

## 10. Security consequences

The protocol prevents forged transactions, reordering of admitted
transactions, backdating below validators' cutoffs, silent feed rewrites
(detected as forks), and replicas disagreeing about state without detection.
It permits a writer to change only rows it owns or was granted, a validator set that
meets the policy to admit any well-formed transaction, and readers to keep
what they were able to decrypt. Compromised writer or validator keys are
handled by revocation; a compromised root key by forking. See the
[threat review](security-threat-review.md).
