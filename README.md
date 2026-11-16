# Chronolog DB

Chronolog DB is a TypeScript prototype of a decentralized, permissioned SQL
database. Members write **ordinary SQLite transactions**. Transactions are
signed, replicated peer to peer, admitted by validator attestations, and
ordered by their immutable author timestamps. Every replica executes them in
that order on a pinned DoltLite (SQLite + Dolt) engine and derives the same
database. When a transaction arrives late, replicas rewind to a checkpoint and
replay from where it belongs. Validators never sign database states.

- **Plain SQL.** DDL and DML travel in one stream; there is no schema manifest,
  dialect or migration system. Assumptions are SQL statements, usually
  `SELECT chronolog_assert(condition, 'code')`; a failing statement rejects the
  whole transaction.
- **Owner-controlled rows.** Every application table automatically gets a
  `chronolog_owner` column stamped with the signer of the insert, stored as a
  small integer id (`chronolog_principals` maps ids to keys).
  Generated triggers let only the owner, a collective it belongs to, or a key
  it granted access update or delete a row; administrators included. Schema
  administrators may run DDL and write app triggers that narrow, never widen,
  those rights. Violations abort the whole transaction
  ([design](docs/design-owner-rows.md)).
- **Explicit encrypted readers.** An owner controls a row's reader policy;
  the client encrypts individual BLOB columns and wraps each fresh value key
  only to those readers. Sealed writes still obey ordinary row grants and
  application triggers. Ownership does not imply decryption rights
  ([guide](docs/sealed-data.md)).
- **Determinism from a pinned engine.** Every replica runs the same engine
  build; `'now'`, `random()` and `localtime` are fixed per transaction; a short
  authorizer block-list keeps statements inside the database.
- **Replication.** Each node keeps signed, hash-chained feeds in one SQLite
  file and pulls the feeds of all group members from its peers over Secure
  Scuttlebutt's authenticated handshake. No record size limit beyond a
  configurable maximum.
- **Governance.** A signed genesis and capability revisions grant writer,
  validator, reader and administrator roles; payloads are encrypted with
  per-epoch keys wrapped to readers. There is no in-protocol recovery: failures
  are handled by forking the group or out of band.

Read [the design](docs/design.md) for how it works,
[Specification 10](docs/implementation-specs/10-deterministic-sql-transactions.md)
for the transaction contract, and [the documentation index](docs/README.md) for
everything else.

## Quick start

Requirements: Node.js 22 or newer, pnpm, Python 3 and a C/C++ toolchain for
`node-gyp`. The first install downloads the pinned DoltLite 0.11.29 source,
verifies its SHA-256 and compiles the patched binding.

```sh
pnpm install
pnpm test
pnpm demo        # two in-memory nodes: an ownership rejection, a grant, and a replay flip
pnpm dev         # persistent daemon on http://127.0.0.1:8787, data in .chronolog/
```

In another terminal:

```sh
pnpm cli status
pnpm cli query 'SELECT * FROM accounts WHERE id = ?' '[1]'
pnpm cli transact @transaction.json
pnpm cli outcome TRANSACTION_ID
```

A transaction file lists steps: SQL statements and platform operations.
Bindings are JSON scalars or tagged values
(`{"kind":"integer","value":"9007199254740993"}`, `{"kind":"real","value":1}`,
`{"kind":"blob","value":"BASE64URL"}`). The daemon's own node is the group's
root administrator, so it may create a table (it is owner-checked from the
next statement on):

```json
{
  "steps": [
    { "sql": "CREATE TABLE accounts (id INTEGER PRIMARY KEY, balance INTEGER NOT NULL) STRICT" },
    { "sql": "INSERT INTO accounts (id, balance) VALUES (?, ?)", "bindings": [1, 100] }
  ],
  "wait": true
}
```

The row now belongs to this node's key. Another node's
`UPDATE accounts SET balance = 0 WHERE id = 1` is rejected with
`policy:accounts:update`, until the owner grants it access:

```json
{ "steps": [{ "platform": "grant", "table": "accounts", "grantee": "BOB_KEY_BASE64URL", "operations": ["update"], "rowKey": [1], "columns": ["balance"] }] }
```

From TypeScript:

```ts
import { platformOp } from '@chronolog/client'

const tx = await client.transaction([
  { sql: "SELECT chronolog_assert((SELECT balance FROM accounts WHERE id = :id) >= 50, 'insufficient_funds')", params: { id: 1 } },
  { sql: 'UPDATE accounts SET balance = balance - 50 WHERE id = :id', params: { id: 1 } },
  platformOp.grant({ table: 'accounts', grantee: bobKey, operations: ['update'], rowKey: [1] }),
])
const outcome = await tx.settled()   // accepted, or rejected with { code, statementIndex }
const rows = await client.query(`SELECT a.id, a.balance, p.key AS owner
  FROM accounts AS a JOIN chronolog_principals AS p ON p.id = a.chronolog_owner`)
```

`platformOp` also builds collectives (`createCollective`, `acceptMembership`,
`setMembers`, `leave`), revocations and transfers (`transferRow`,
`transferAll`, `acceptTransfer`); the CLI accepts the same operations as
`{"platform": ...}` steps (see `apps/chronolog/src/main.ts`).

Set `CHRONOLOG_URL`, `CHRONOLOG_GROUP_ID` and `CHRONOLOG_TOKEN` for a
non-default daemon. RPC refuses a non-loopback bind without a token.

## Running a group

The daemon creates a signed governance genesis on first start; the local
identity is administrator, writer, validator and reader. To add nodes, use
`pnpm group descriptor` / `pnpm group join` and grant the printed capabilities
with `pnpm cli governance grant`; see the [governance guide](docs/governance.md).
Peers are configured with:

```sh
CHRONOLOG_SSB_HOST=0.0.0.0 CHRONOLOG_SSB_PORT=8008 CHRONOLOG_SSB_SCOPE=public \
CHRONOLOG_SSB_PEERS='[{"address":"net:host:8008~shs:PUBLIC_KEY","feedId":"@FEED.ed25519"}]' \
pnpm dev
```

A node replicates its configured peers' feeds and the feed of every granted
member, relayed through any connected peer. The secret handshake authenticates
the connection; Chronolog independently verifies every record's feed
signature, the inner protocol signature, the capability revision, the
validation policy and the encryption epoch.

Operational tools: `pnpm snapshot export|import|repair` (signed archives and
feed repair), `pnpm group fork|verify-fork` (forking a group),
`pnpm release:distribution` (relocatable native archive), and
`chronolog doctor`. See the [pilot runbook](docs/pilot-runbook.md).

`CHRONOLOG_STATIC_MEMBERSHIP_FILE` is a testing override that replaces
governance with a fixed out-of-band membership file; its `rootAdministrator`
key is the first schema administrator.

## Testing

```sh
pnpm test               # unit and integration tests
pnpm conformance        # replay-equivalence report for this engine build
pnpm test:soak          # long replay soak
pnpm chaos:smoke        # container P2P fault runs (also :crash, :stress)
```

See the [chaos testing guide](docs/chaos-testing.md) and the
[release-hardening guide](docs/release-hardening.md).

## Workspace

| Package | Responsibility |
| --- | --- |
| `canonical` | Strict bounded CBOR, bytes, typed hash domains |
| `protocol` | Signed messages, program (SQL and platform-operation) and value codecs, execution manifest, order keys |
| `capabilities` | Genesis, grants, revocations, validation policy |
| `crypto` | HPKE, signed epochs, content encryption |
| `transport-ssb` | SQLite signed-feed store, replication over the SSB handshake, in-memory simulator |
| `control-store` | Candidates, attestations, order, heartbeats, settlement evidence |
| `node-core` | Ingestion, admission, attestation, encryption, orchestration |
| `materializer-doltlite` | Deterministic SQL execution, owner-controlled rows (platform operations, generated triggers), Dolt checkpoints, suffix replay, local SQL |
| `materializer` | Portable materialization contracts shared with the workerd path |
| `runtime-workerd` | Experimental workerd execution contract ([plan](docs/workerd-reconstruction-plan.md)) |
| `rpc` | Service contract, in-process and HTTP transports |
| `client` / `react` | TypeScript client and React hooks |
| `conformance` | Replay-equivalence and release characterization |
| `chaos` | Container topology, faults, workloads, invariant checks |
| `testkit` | Clocks, permutations, network helpers |

## Status

A comprehensive prototype, not a production release. Remaining work before
production: witnessed pilot drills, hardware-backed key providers, the open
security findings, and an external security review. See
[implementation status](docs/implementation-status.md) and
[upcoming work](upcoming.md).
