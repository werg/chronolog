# Chronolog DB

Chronolog DB is a TypeScript prototype of a decentralized, permissioned
application log. One signed change program combines **ordinary SQLite
transactions**, platform operations, and bounded durable events. Native and
browser peers verify the same original records; SQL profiles execute the same
pinned DoltLite engine, and event-only profiles do not load it. A signed
genesis selects an inclusion/finality provider. Every provider uses the same
deterministic application order: author timestamp, signing key, proposal ID.
Validators or an external service can prove inclusion and close a timestamp
prefix; neither supplies an execution order. SQL executes locally. Tendriller
can serve the page and administer participants while application exchange runs
over authenticated WebRTC between Chronolog peers. A retained-log adapter is an
explicit alternative deployment choice.

Peer history can replay a tentative suffix when a late transaction arrives.
The signed-inclusion provider retains receipts and durable closure promises;
receipt positions never order SQL or effective events. Newly included backdated
proposals cannot reopen a closed prefix. Custom verifiers are selected by the
provider ID and parameters signed in genesis.
Both expose separate local and final SQL revisions, durable submission identity,
and live scoped reader/writer enrollment. Start with the
[application primitives guide](docs/application-primitives.md) for choosing APIs,
finality, replay and role boundaries. The [resident agent](packages/agent-service/README.md)
and [pluggable finality](docs/pluggable-finality.md) explain the architecture;
the [application-log report](docs/plans/application-log.md) tracks qualification.
The [peer application architecture](docs/peer-application-architecture.md) describes
the boundary between page hosting, compact membership, live signals and durable
application work.

- **Plain SQL.** DDL and DML travel in one stream; there is no schema manifest,
  dialect or migration system. Assumptions are SQL statements, usually
  `SELECT chronolog_assert(condition, 'code')`; a failing statement rejects the
  whole transaction.
- **Atomic events.** Accepted programs expose whole-proposal event batches with
  stable IDs; rejected programs expose no effective events. Final event readers
  use bounded pull delivery and history/filter-bound cursors, including progress
  across nonmatching records. Local projections atomically checkpoint state and
  processed progress outside the consensus core.
- **Ephemeral signals.** `client.signals` carries typing, presence, cursors and
  replaceable progress without retained history, transactional execution or a
  finality provider. The standalone `@chronolog/signals` package also works
  without a database or Chronolog membership. Group adapters add explicit
  signal rights; durable topic rights do not implicitly grant them.
- **Coherent views.** A bounded read lease pins SQL and effective events to one
  view. Provisional rebases replace that view; finality and operation status can
  advance even when rows stay equal.
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
- **Replication.** Native SQLite and browser OPFS adapters share the original
  signed-record codec, immutable evidence, and range/stream synchronization.
  WebRTC, native SSB connections and the optional retained-log adapter supply connectivity;
  a relay never changes original authorship.
- **Governance.** A signed genesis fixes the consensus roles and history
  policy. Live signed enrollment grants reader/writer access with explicit
  historical-key approval. Writes bind their exact grant, and revocations
  activate at verified policy boundaries. Epoch keys are wrapped to readers.
  SQL, durable topic and ephemeral signal rights are distinct. Limited
  publishers use original-signer ingress without reader keys or a local replica.
- **Resident work.** Final-intent workers own timer generations and durable
  dispatch checkpoints in a fenced native store. A native finality service can
  run alongside them, or a replica can consume proofs from another provider.
  External effects require provider idempotency/reconciliation or an explicit
  uncertain state.

Read [the design](docs/design.md) for how it works,
[Specification 10](docs/implementation-specs/10-deterministic-sql-transactions.md)
for the transaction contract, and [the documentation index](docs/README.md) for
everything else.

## Quick start

Requirements: Node.js 22 or newer, the pinned pnpm 10.12.4, Python 3 and a C/C++ toolchain for
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

A CLI transaction file lists SQL statements and platform operations. Use the
public client's `submit` and `events` APIs below for event-only or mixed programs.
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
const provisional = await tx.settled()  // current accepted/rejected result
const outcome = await tx.final()         // actual applied final result
const rows = await client.query(`SELECT a.id, a.balance, p.key AS owner
  FROM accounts AS a JOIN chronolog_principals AS p ON p.id = a.chronolog_owner`)
```

`platformOp` also builds collectives (`createCollective`, `acceptMembership`,
`setMembers`, `leave`), revocations and transfers (`transferRow`,
`transferAll`, `acceptTransfer`); the CLI accepts the same operations as
`{"platform": ...}` steps (see `apps/chronolog/src/main.ts`).

## Application events and pinned views

Programs and manifests are pre-release formats: `ChangeProgram` is version 3,
and its signed transaction core binds a stable `operationId`. Reusing that ID
with different program bytes fails. Exact retries recover the original proposal
and outcome, including after a writer grant is revoked.

```ts
import { emit, program, sqlStatement } from '@chronolog/protocol'

const claim = await client.submit(program(
  sqlStatement("SELECT chronolog_assert((SELECT claimed_by IS NULL FROM tasks WHERE id = ?) = 1, 'already_claimed')", ['task-1']),
  sqlStatement('UPDATE tasks SET claimed_by = ? WHERE id = ?', ['member-1', 'task-1']),
  emit('tasks/claimed', { taskId: 'task-1', memberId: 'member-1' }),
), { operationId: 'claim-task-1' })
await claim.final()

const view = await client.readView({ view: 'final' })
try {
  const tasks = await view.query('SELECT id, claimed_by FROM tasks')
  const events = await view.readEvents({ topics: ['tasks/claimed'] })
  // Publish the combined UI only after both reads from this view finish.
  render({ revision: view.revision, tasks, events })
} finally { await view.release() }
```

The schema/row grants and topic rights must authorize this program. Durable
workers consume `client.events` or `node.events`; use `DurableProjection` with
an atomic store for replayable frontend caches. Received cursors are not durable
processed checkpoints. Typing and replaceable progress use `client.signals`:

```ts
await client.signals.send('presence/typing', { active: true }, { ttlMs: 3_000 })
```

Signals are best-effort and have no replay or final outcome. Publish a durable
result when persistence matters. See the [signals contract](packages/signals/README.md)
for bounded subscriptions, expiration and standalone use.

`@chronolog/runtime-browser/events` opens the SQL-free OPFS Worker profile and
exports `WorkerRpcTransport`. Its exclusive owner, synchronous private control
journal and durable outbox preserve restart semantics without a WASM engine.
The SQL profile retains the real pinned engine and isolated-Worker requirements.

The [contrib pilot](https://github.com/werg/tendriller-contrib/pull/13) contains
two task/chat layouts using the public application backend and the resident
worker's actual request/result envelopes. Real deployment network routes,
cost, disk-loss recovery and privacy/device qualification remain separately
tracked there.

Set `CHRONOLOG_URL`, `CHRONOLOG_GROUP_ID` and `CHRONOLOG_TOKEN` for a
non-default daemon. RPC refuses a non-loopback bind without a token.

## Running a group

The daemon creates a signed governance genesis on first start. It pins the local
identity as membership issuer and initial SQL schema administrator, and gives
it explicit writer, validator and reader grants. New devices adopt the
public descriptor, then use the live `client.enrollment` request/approval/status
flow with explicit full-history access. The fixed validator set does not change.
See the [governance guide](docs/governance.md) and [client API](packages/client/README.md).
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
| `records` | Portable original signed records, immutable evidence, durable storage and shared range/stream synchronization |
| `transport-ssb` | Native SQLite record/evidence storage and authenticated SSB connections |
| `transport-webrtc` | Bounded RTC framing, HTTPS introduction, observed ICE routes and session supervision |
| `transport-tendriller` | Optional public retained-log adapter and on-demand finality service |
| `signals` | Portable signed live messages, bounded subscriptions and explicit delivery lifetime |
| `agent-service` | Governed peer routing, native finality, resident effects and timer workers |
| `control-store` | Candidates, attestations, order, heartbeats, settlement evidence |
| `node-core` | Governed peer composition, two history policies, durable operations, live enrollment, admission and finality |
| `materializer-doltlite` | Deterministic SQL execution, owner-controlled rows (platform operations, generated triggers), Dolt checkpoints, suffix replay, local SQL |
| `materializer` | Portable materialization contracts shared with the workerd path |
| `runtime-browser` | Owning Worker, OPFS, Web Lock, patched DoltLite WASM and shared client RPC |
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
