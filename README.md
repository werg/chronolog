# Chronolog

Chronolog is a *freely programmable reducer* for time-ordered data for JS runtimes (client and server), which gives CRDT semantics to arbitrary linear-time algebraic data structures, including complex ones like a SQL database.

- It is **freely programmable and boostrapped** in the sense that a computer is programmable: The initial operation defines the rules (code) by which subsequent operations will be reduced, including the rules for updating the rules as part of the state, as well as other control state such as permissions and membership (again freely adaptable to the needs of the peers that share the data).

- To achieve CRDT semantics, Chronolog simply applies rollback-and-replay to all parts of its state so that all operations are applied in temporal order. For SQL this means: enforcing determinism, ordering transactions by timestamp and facilitating the use of pre-conditions to gate transactions on their state assumptions. The function that updates the database is just another reducer function stored in the state of the Chronolog CRDT.

Chronolog also has some logic for p2p exchange, operation admission based on state-defined permissions and connectors to optional consensus / finality controllers which can help avoid maliciously backdated operations (a vulnerability of purely time-ordered eventually consistent protocols that do not have full trust in their participants).

## Core Model

Chronolog rests on three interlocking design choices:

### 1. A Flat, Timestamp-Ordered Operation Set

A Chronolog log is modeled as an **unordered set** of standalone, Ed25519-signed operations scoped to a genesis hash (`logId`). Operations do not carry parent hashes, block pointers, or causal edges;  while it is content-addressable in its aggregated state, this is not a blockchain.

Instead, every replica derives the same canonical total order solely by sorting the operations it has observed by:

```text
(authorTimestampMs ASC, authorPublicKey ASC, opId ASC)
```

No peer, relay, host, or validator assigns operation order. Replicating between two peers is simply set union of signed operations and the content-addressed blobs they reference.

### 2. Generalized Rollback-and-Replay over Content-Addressed State

Building on the undo-do-redo model for replicated logs, Chronolog treats convergence as a property of deterministic reduction rather than of specialized data structures:

```text
State  = Map<TopicName, StateValue>
Kernel : (State, Operation) -> State
```

Any deterministic transition function over content-addressed state becomes strongly eventually consistent automatically:

- **Offline authoring:** Devices sign and persist operations locally before any network I/O and immediately materialize them against local state.
- **O(1) rewind on late arrivals:** When an operation with an earlier timestamp arrives later from a reconnecting peer, the runtime does not require inverse functions or custom merge logic. It rewinds in O(1) to a cached content-addressed snapshot preceding that timestamp and deterministically replays the suffix.
- **Deterministic replay guarantees:** Reducers run inside a fresh QuickJS-NG WebAssembly sandbox per invocation with non-deterministic globals (`Date`, `Math.random`, `Intl`) removed. Missing content-addressed dependencies halt replay via an uncatchable host interrupt until fetched, preventing divergent error handling.

### 3. A Self-Describing Kernel ("Reducer of Reducers")

At the lowest level, the kernel does not hardcode application schemas, access control rules, key management, or finality policies. State is a map of named **topics**, and one reserved control topic—`$reducers`—stores an Import Map of hash-pinned ES Modules (`specifier -> cas:sha256-...`) alongside the mapping from each topic name to its reducer module.

When applying an operation, the kernel inspects `$reducers` in the *current* materialized state, loads the target topic's module from content-addressed storage, and executes `reduce(state, tx, ctx)`.

Because reducer definitions live inside the state being folded:

- **Evolving or frozen rules:** Binding `$reducers` to a governance reducer (such as admin-gated or M-of-N multisig updates) lets schemas, business logic, and permissions evolve at exact points in logical history—and unwind cleanly if an earlier operation triggers suffix replay. Leaving `$reducers` unbound at genesis freezes the log's rules permanently.
- **Uniform mechanism for control plane and data plane:** Membership (`$permissions`), encryption epochs (`$keys`), finality schedules (`$finality`), static application manifests (`$publications`), and ephemeral signal rules (`$signal_policy`) are all ordinary topics governed by standard, auditable ES module reducers.

---

## SQLite as a Replicated Topic (`chronolog-db` and `chronolog/sql`)

Because rollback-and-replay applies to any deterministic reducer over content-addressed storage, a full relational database becomes a standard topic reducer (`chronolog/sql`) rather than a bespoke replication protocol.

### Merkle-Paged SQLite in WebAssembly

`chronolog-db` compiles stock SQLite with **FTS5** (full-text search) and **`sqlite-vec`** (vector search) to a static WebAssembly module (`sqlite-cas.wasm`) backed by a 4 KiB Merkle-paged VFS over Chronolog's content-addressed store:

- **Database state as a 32-byte root hash:** Each transaction commit flushes only dirty 4 KiB pages into content-addressed storage and returns a new `dbRoot` hash. Rolling back a rejected transaction or rewinding across `CREATE TABLE`, `ALTER TABLE`, indexes, and triggers is an O(1) root pointer swap.
- **Multi-database logs:** A single log can bind multiple topics to `chronolog/sql` to maintain isolated relational databases under one identity, encryption, and permission boundary, and a single signed operation can update multiple topics atomically.
- **Deterministic SQL profile:** `random()` and `randomblob()` are disabled; `datetime('now')` and `localtime` resolve to the signed operation's UTC timestamp (`op_time()`); and the host kernel binds `actor()`, `op_id()`, and `op_time()` directly into SQLite so callers cannot spoof identity or timestamps.

### Optimistic Concurrency with Preconditions and Postconditions

In a local-first system, an operation authored offline may later replay against a different state than the author originally saw. Every `chronolog/sql` transaction accepts declarative, read-only SQL `preconditions` and `postconditions`:

```json
{
  "preconditions": [
    {
      "sql": "SELECT units >= ? AND units = ? FROM bins WHERE id = ?",
      "params": [2, 10, "source"],
      "code": "balance_changed"
    }
  ],
  "statements": [
    { "sql": "UPDATE bins SET units = units - ? WHERE id = ?", "params": [2, "source"] },
    { "sql": "UPDATE bins SET units = units + ? WHERE id = ?", "params": [2, "destination"] },
    { "sql": "INSERT INTO transfers (id, from_bin, to_bin, units, by_actor) VALUES (?, ?, ?, ?, actor())", "params": ["tx-42", "source", "destination", 2] }
  ],
  "postconditions": [
    {
      "sql": "SELECT NOT EXISTS (SELECT 1 FROM bins WHERE units < 0)",
      "code": "negative_balance"
    }
  ]
}
```

If any precondition, postcondition, SQL constraint, or row-level trigger fails, the transaction rolls back atomically (`dbRoot` is unchanged) and records a deterministic rejection code, while the original signed operation remains intact in the operation set. At the operation level, authors can also express explicit causal dependencies (such as `afterOps` or `requiresRejected` for compensating actions).

### Row-Level Write Policies and User-Owned DDL

`chronolog/sql` combines SQLite's C-level authorizer (`admin`, `user`, `readonly`) with `chronolog/rls` to enforce fine-grained collaborative access control:

- **Declarative write RLS:** Administrators define per-table `insert`, `update`, and `delete` predicates using `NEW.*`, `OLD.*`, `actor()`, `op_id()`, `op_time()`, and read-only subqueries against any table in the database. Each predicate is statically validated through the `readonly` authorizer before being compiled into `BEFORE INSERT/UPDATE/DELETE` triggers that non-admin transactions cannot alter or drop.
- **Evolvable schemas and policies:** Tables and RLS rules are created or updated through ordinary signed migrations, and the active schema and policies can be introspected deterministically at any snapshot.
- **User-owned tables:** When `allowUserDdl` is enabled, non-admin writers can create, alter, index, and drop their own tables while remaining isolated from administrator tables and other users' DDL.

---

## Supporting Architecture

Several ancillary mechanisms make the flat operation-set model practical for real collaborative applications:

### Public/Encrypted Partitioning and Blind Hosting

On private logs (`privateLog: true`), the kernel enforces a strict two-way partition:

- **Control topics (`$*`)** are mutated only by `public` (unencrypted) operations and may read only `$*` topics and public content-addressed nodes.
- **Application topics** are mutated only by `encrypted` operations wrapped under an epoch key.
- **Partition-scoped idempotency:** Deduplication is keyed by `(visibility, author, operationId)` and authenticated in the state root.

As a result, an untrusted relay or edge server (such as a Cloudflare Worker) can run the exact same kernel in `blindHostMode` with zero decryption keys, processing only public operations and deriving bit-for-bit identical `$reducers`, `$permissions`, `$keys`, `$finality`, and `$publications` state as full replicas.

### End-to-End Encryption and Offline Reconnect Rewrapping

Each device holds a persistent Ed25519 signing identity and an X25519 wrapping key. The `$keys` topic stores per-epoch commitments and HPKE (`DHKEM(X25519)/HKDF-SHA256/AES-256-GCM`) lockboxes for authorized readers.

Encrypted envelopes are reconciled by ciphertext digest rather than by `opId` alone. If an offline peer authors operations under epoch `e` while online peers rotate to epoch `e + 1`, the reconnecting peer unseals epoch `e + 1` from `$keys`, re-encrypts its exact original signed operation bytes under the new epoch—preserving the original `opId`, `authorTimestampMs`, and Ed25519 signature—and synchronizes the new envelope without losing history or perturbing ordering.

### Pluggable Authority (`$permissions`)

Access control is decoupled from the runtime through a minimal capability query contract (`reader`, `writer`, `administrator`, `publisher`, `finalizer`, plus optional scoped and expiring grants). Three standard authority models ship out of the box—or an application can supply its own reducer:

- **`attestedMembers`:** Explicit member roster with optional host-signed admission attestations, invite management, and M-of-N guardian key recovery.
- **`multisigMembers`:** Zero-host M-of-N threshold governance over proposals and approvals.
- **`openMembers`:** Public read/write logs with administrator governance, author blocking, and optional vouching/anti-spam controls.

### Consensus-Agnostic, Time-Scoped Finality (`$finality`)

Chronolog separates **ordering** from **finality**. Ordering is always canonical via `(authorTimestampMs, author, opId)`, while finality is an optional, monotonically scheduled policy stored in `$finality`:

| Mode                  | `$finality` Policy                     | Properties                                                                                                                                                                                                                                                  |
| --------------------- | -------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Pure CRDT**         | `none`                                 | No coordinators or consensus. Every operation is immediately live and history remains open to earlier offline arrivals.                                                                                                                                     |
| **Checkpointed CRDT** | `signed-frontier` or `fixed-validator` | Peers collaborate offline while a notary or M-of-N validator set periodically seals `closedThroughMs` checkpoints. Operations claiming timestamps at or before the closed frontier that were not included in the checkpoint are deterministically excluded. |
| **External Anchor**   | `blockchain-anchor`                    | Finality checkpoints and inclusion commitments are anchored to an external ledger while retaining the same local reducer and SQL execution model.                                                                                                           |

A log can transition across policies over time (for example, starting with `none` and later enabling a validator set, or handing off from one validator set to another). New replicas can bootstrap from a verified finality checkpoint plus suffix operations and arrive at the exact same `stateRoot` and `revision.digest` as replaying from genesis.

### Reactive Snapshots, Event Forwarding, and Ephemeral Signals

Because late earlier-timestamped operations can revise materialized state, consumers should not assume an append-only stream of permanent changes:

- **Reactive views (`createLiveView`):** Derives application UI state from coherent read snapshots (`ApplicationReadView`) whenever materialization advances or rewinds, with optional topic and SQL-table invalidation filters.
- **Durable event forwarding (`forwardSessionEvents`):** Reconciles emitted reducer events against the current effective snapshot for external side effects (webhooks, notifications, background agents), issuing explicit retraction callbacks if a late operation alters a provisional outcome.
- **Ephemeral live lane (`@chronolog/signals`):** Presence, cursors, typing indicators, and streaming tokens travel over a separate signed, bounded ephemeral channel authorized against `$signal_policy` without entering the durable operation set.
- **Content-addressed storage and binary attachments:** Reducers, SQLite pages, and derived replay snapshots share one Merkle-DAG `ContentAddressedStore` with exact mark-and-sweep garbage collection. Large media and file attachments use a streaming, chunked blob interface (`session.content`) with epoch encryption and bounded local cache eviction.

---

## Standard Modules

Chronolog pins a suite of audited ES Modules into public content-addressed storage at genesis:

| Category            | Module                     | Purpose                                                                                                                                              |
| ------------------- | -------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Control Plane**   | `chronolog/permissions`    | `attestedMembers`, `multisigMembers`, `openMembers`, admin-only `$reducers` governance, and default `$signal_policy`.                                |
|                     | `chronolog/keys`           | HPKE epoch key lockboxes, key rotation, and historical epoch grants for newly admitted devices.                                                      |
|                     | `chronolog/finality`       | Time-scoped finality schedule (`none`, `signed-frontier`, `fixed-validator`, `blockchain-anchor`) and handoff rules.                                 |
|                     | `chronolog/publications`   | Signed static web application release manifests referencing public CAS hashes.                                                                       |
| **Relational SQL**  | `chronolog/sql`            | First-class SQLite-CAS topic reducer with migrations, declarative preconditions/postconditions, write RLS, user-owned DDL, and schema introspection. |
|                     | `chronolog/rls`            | Static `readonly` validation and trigger generation (`applyRls`) for Postgres-style row-level write policies.                                        |
|                     | `chronolog/sqlite-helpers` | Helpers (`defineSqlReducer`, `withDb`, `rowsToObjects`) for building custom SQLite-backed reducers with schema introspection.                        |
| **Data Structures** | `chronolog/crdt`           | Out-of-order-safe Last-Write-Wins maps and set/counter primitives.                                                                                   |
|                     | `chronolog/text`           | RGA collaborative text editing with stable character identifiers.                                                                                    |
|                     | `chronolog/ledger`         | Double-entry accounts, holds, and allowances.                                                                                                        |
|                     | `chronolog/workflow`       | Role-gated state machines with multi-approval transitions.                                                                                           |
|                     | `chronolog/fs`             | Hierarchical path tree with deterministic conflict naming.                                                                                           |

---

## Usage

### 1. Creating and Querying a Replicated SQL Log

Bind any topic to `chronolog/sql` in `createLogGenesis` to get an encrypted, replicated SQLite database with write RLS and declarative transactions:

```ts
import { createLogGenesis, createApplicationSession } from '@chronolog/peer-session'
import { openNativeDevice } from '@chronolog/peer-session/native'

const device = await openNativeDevice({ path: './app.sqlite', create: true })

const created = await createLogGenesis({
  creator: {
    publicKey: device.identity.publicKey,
    wrapKey: device.wrapKey.publicKey,
    reader: true,
    writer: true,
    administrator: true,
  },
  topics: {
    tasks: { module: 'chronolog/sql' },
  },
})

const session = await createApplicationSession({
  device,
  genesis: created.genesisBytes,
  casNodes: created.casNodes,
  epochKeys: new Map([[0, created.epoch0Key!]]),
})

// 1. Signed DDL migration with row-level write policies
await (await session.submit({
  updates: [{
    topic: 'tasks',
    input: {
      action: 'migrate',
      statements: [
        'CREATE TABLE tasks (id TEXT PRIMARY KEY, owner TEXT NOT NULL, title TEXT NOT NULL, claimed_by TEXT)',
      ],
      policies: {
        tasks: {
          insert: 'NEW.owner = actor()',
          update: 'OLD.owner = actor() OR OLD.claimed_by IS NULL OR OLD.claimed_by = actor()',
          delete: 'OLD.owner = actor()',
        },
      },
    },
  }],
})).materialized()

// 2. Optimistic transaction with atomic precondition check
await (await session.submit({
  updates: [{
    topic: 'tasks',
    input: {
      preconditions: [
        { sql: 'SELECT COUNT(*) = 0 FROM tasks WHERE id = ?', params: ['t1'], code: 'already_exists' },
      ],
      statements: [
        { sql: 'INSERT INTO tasks (id, owner, title) VALUES (?, actor(), ?)', params: ['t1', 'Draft architecture notes'] },
      ],
    },
  }],
})).materialized()

// 3. Deterministic read-only query and schema introspection
const rows = await session.query('tasks', {
  sql: 'SELECT id, owner, title FROM tasks ORDER BY id',
  format: 'objects',
})
const schema = await session.query('tasks', { query: 'schema' })
console.log(rows.value, schema.value)

await session.close()
```

### 2. Synchronizing Replicas and Subscribing to Reactive Views

Peers synchronize over direct WebRTC connections, WebSocket relays (`session.connectPeer`), or transport-agnostic fact exchange (`exportFacts` / `mergeFacts`):

```ts
import { createLiveView } from '@chronolog/peer-session'

// Transport-agnostic sync (e.g., over HTTP, files, or custom messaging)
const facts = await sessionA.exportFacts()
await sessionB.mergeFacts(facts)

// Coherent reactive snapshot subscription (automatically re-derives on forward updates or suffix replay)
const liveTasks = createLiveView(
  sessionB,
  async (view) => view.query('tasks', { sql: 'SELECT id, title FROM tasks ORDER BY id', format: 'objects' }),
  { watchTopics: ['tasks'], watchTables: ['tasks'] },
)

const stop = liveTasks.subscribe(({ revision, value }) => {
  console.log(revision.stateRoot, value)
})
await liveTasks.ready()
```

For live peer-to-peer links, pass a WebRTC (`@chronolog/peer-session/webrtc`) or WebSocket (`@chronolog/peer-session/websocket`) framed connection into `session.connectPeer({ connection })`.

### 3. Writing a Custom Topic Reducer

Any deterministic ES module exporting `reduce(state, tx, ctx)` (and optionally `query` and `describe`) can be hash-pinned in `createLogGenesis`:

```ts
const counterModule = `
export default {
  reduce(state, tx, ctx) {
    if (!ctx.query('$permissions', { check: 'writer', actor: tx.author })) {
      return { ok: false, code: 'writer_required' };
    }
    const count = typeof state === 'number' ? state : 0;
    if (tx.payload?.action === 'increment') {
      const next = count + (tx.payload.delta ?? 1);
      return { ok: true, state: next, events: [{ topic: 'counter.changed', payload: { count: next } }] };
    }
    return { ok: false, code: 'unknown_action' };
  },
  query(state) {
    return typeof state === 'number' ? state : 0;
  },
};
`

const created = await createLogGenesis({
  creator: { publicKey: device.identity.publicKey, wrapKey: device.wrapKey.publicKey, reader: true, writer: true, administrator: true },
  imports: { 'app/counter': counterModule },
  topics: { counter: { module: 'app/counter' } },
})
```

---

## Runtime Architecture and Portability

```text
Signed Operations (flat set ordered by authorTimestampMs, author, opId)
        │
        ▼
  TopicKernel (TS) ──► QuickJS-NG WASM Sandbox (Import Map from $reducers)
        │                     │
        │                     ├── chronolog/sql       (declarative SQL, preconditions, RLS)
        │                     ├── chronolog:sqlite    (SQLite + FTS5 + sqlite-vec on 4 KiB Merkle CAS)
        │                     ├── chronolog:crypto    (sha256, verifyEd25519, canonicalJson)
        │                     ├── chronolog:cas       (explicit-link content-addressed put/get)
        │                     └── Standard & custom ES module reducers
        ▼
  ContentAddressedStore (Merkle-DAG CAS, public/private partitions, mark-and-sweep GC)
        │
        ▼
  BytesStore (Memory | Browser OPFS / IndexedDB | Node 22+ built-in node:sqlite)
```

Chronolog requires **Node.js >= 22.15** and has **no native C/C++ build dependencies** (`node-gyp` is not used):

- **Node.js:** Durable storage runs on Node's built-in `node:sqlite` (`DatabaseSync`).
- **Browsers:** A dedicated Web Worker owns keys, locks, storage (OPFS or IndexedDB), and reducer execution; the main thread imports a passive RPC facade (`@chronolog/peer-session/browser`) that never eagerly loads storage, QuickJS, or SQLite.
- **Edge runtimes (Cloudflare Workers):** Both QuickJS-NG and `sqlite-cas.wasm` accept pre-compiled `WebAssembly.Module` instances, avoiding runtime WASM compilation.

### Repository Packages

| Package                          | Responsibility                                                                                                 |
| -------------------------------- | -------------------------------------------------------------------------------------------------------------- |
| `@chronolog/canonical`           | Deterministic CBOR encoding, hashing, and canonical serialization.                                             |
| `@chronolog/crypto`              | Ed25519 signing, X25519 key agreement, HPKE, and AES-256-GCM primitives.                                       |
| `@chronolog/protocol`            | Genesis, operation, encrypted envelope, and wire format definitions.                                           |
| `@chronolog/records`             | `BytesStore` implementations, Merkle-DAG `ContentAddressedStore`, and framed channels.                         |
| `@chronolog/authority`           | Portable signed records, input schemas, and time-scoped `$finality` verification (zero runtime/SQL imports).   |
| `@chronolog/materializer`        | `TopicKernel`, `QuickJsSandbox`, and the standard ES module library.                                           |
| `chronolog-db`                   | Deterministic SQLite + FTS5 + `sqlite-vec` WASM driver over a 4 KiB Merkle-paged CAS VFS.                      |
| `@chronolog/signals`             | Signed, bounded ephemeral live-lane messaging.                                                                 |
| `@chronolog/transport-webrtc`    | Direct WebRTC data-channel and media transport with in-band negotiation.                                       |
| `@chronolog/transport-websocket` | WebSocket framed peer channel transport.                                                                       |
| `@chronolog/peer-session`        | Unified `ApplicationSession`, device management, replication, snapshots, reactive views, and worker ownership. |

---

## Development

```sh
pnpm install --frozen-lockfile
pnpm lint && pnpm typecheck && pnpm test && pnpm build && pnpm docs:check
```

To build standalone distributable tarballs:

```sh
pnpm package:authority   # Portable @chronolog/authority tarball
pnpm package:session     # Universal zero-native-build @chronolog/peer-session tarball
```

## Documentation

- [Chronolog CRDT Contract](docs/CRDT_CONTRACT.md) — formal invariants for ordering, public/encrypted partitioning, QuickJS-NG Import-Map reducers, deterministic SQLite-CAS, write RLS, keys, finality, and signals.
- [Authored Operation-Set Guide](docs/authored-operation-set.md) — operation lifecycle, offline authoring, reconnect rewrapping, reactive views, and checkpoint bootstrap.
- [Browser Storage Architecture](docs/browser-storage.md) — OPFS, IndexedDB, capability probing, and single-owner worker isolation.
- [Documentation Index](docs/README.md) — package guides for `@chronolog/peer-session`, `@chronolog/materializer`, `chronolog-db`, `@chronolog/authority`, `@chronolog/signals`, and `@chronolog/transport-webrtc`.
