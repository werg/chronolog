# Chronolog

**Universal deterministic undo-do-redo over a flat set of signed operations — a minimally bootstrapped reducer of reducers, with a full vanilla SQLite database as a CRDT (`chronolog-db`), malleable write RLS, declarative transaction preconditions, and a consensus-agnostic finality layer.**

Chronolog lets browsers, Node.js agents, and blind edge hosts (such as Cloudflare Workers) author offline and converge bit-for-bit to the exact same state — with **zero native C/C++ builds**, no central sequencer, and no mandatory consensus protocol.

---

## Why This Exists

Most distributed systems force an unnecessary fork in the road:

- **Pick a CRDT**, and you are trapped designing bespoke algebraic data types (LWW registers, RGA lists, OR-Sets) that shatter the moment you want a unique constraint, a foreign key, a balance transfer, or a relational join.
- **Pick a replicated SQL database**, and you end up wrapping a mutable native binary around a central leader or bolting on lossy per-column LWW merge hacks that silently break invariants.
- **Pick a blockchain**, and you get deterministic state transitions and finality, but you pay for global consensus on every keystroke, lose offline authoring, and inherit a rigid virtual machine.

Chronolog collapses all three into a single, radical abstraction:

> **What if a CRDT weren't a special data structure at all — just a pure, deterministic fold over a flat set of signed operations, where "undo-do-redo" applies to *anything*, and the rules of the fold live inside the state being folded?**

---

## 1. Generalized Undo-Do-Redo — Applied to *Anything*

Inspired by Martin Kleppmann's work on timestamp-ordered operation logs with rollback-and-replay, Chronolog pushes the idea all the way to the bottom:

- **A flat set of independent operations — expressly *not* a Merkle chain:** Every mutation is an immutable, standalone Ed25519-signed operation stamped with `(authorTimestampMs, author, opId)` and scoped by `logId` (the hash of its `LogGenesis`). Input operations **never** reference preceding operations, blocks, or state roots by hash; there are no `parents` pointers and no forks to merge. Individual operations may reference content-addressed CAS hashes for blobs or module code, while remaining independent timestamp-sorted records.
- **One total order, zero sequencers:** Every replica sorts the set of operations it has seen by `(authorTimestampMs, author, opId)` and folds them forward deterministically. No peer, relay, host, or validator ever assigns operation order.
- **Offline first, instant cold reopen & O(1) rewind on late arrivals:** Author locally and durably without waiting for a network or quorum. `ApplicationSession` automatically caches self-verifying materialized state locally (`materialized-cache`) — and exports portable **epoch-AEAD-encrypted snapshots** (`exportMaterializedSnapshot` / `importMaterializedSnapshot`) for ephemeral edge participants — turning cold reopens into **O(1)** or suffix-only catch-up. When an earlier-timestamped operation arrives later from a reconnecting peer, Chronolog doesn't need inverse functions or custom merge logic — it jumps back in **O(1)** to the nearest content-addressed snapshot before that timestamp and deterministically replays the suffix.
- **One pure Merkle-DAG CAS + unified streaming P2P content pipe:** Large immutable values — reducer ES Module source code, SQLite database pages, and *derived* replay snapshots — live in one content-addressed DAG (`ContentAddressedStore`) with explicit links, strict public/private partitions, `session.readCasPayload`, and exact mark-and-sweep garbage collection. Rich media and large attachments flow through `session.content` (`put`, `get`, `putStream`, `readStream`, `pin`, `unpin`, `stats`, `pruneCache`) with epoch encryption or public hash addressing and bounded LRU cache eviction. Input operations remain an unlinked flat set.

---

## 2. The Minimal Bootstrap: A Reducer of Reducers

At the very bottom, Chronolog is gloriously minimal abstract nonsense: **one universal reducer** whose state is a map of named topics:

```text
State  = Map<TopicName, StateValue>
Kernel : (State, Operation) -> State
```

Here is the trick that makes the whole machine self-describing:

**One of those topics — `$reducers` — is itself a piece of state describing the reducers for every topic in the state.**

Specifically, `$reducers` holds an **Import Map** of hash-pinned ES Modules (`specifier -> cas:sha256-...`) and a **topic registry** mapping each topic name to its reducer module. On every operation, the host `TopicKernel` reads `$reducers` from the *current* state, loads the target topic's hash-pinned ES Module from CAS into a fresh, deterministic QuickJS-NG WASM sandbox (with `Date`, `Math.random`, and `Intl` stripped), and executes `reduce(state, tx, ctx)`.

Look at what falls out of reducing *state that contains the reducers over other topics of its own state*:

- **Self-evolving or permanently frozen:** Bind `$reducers` itself to a governance reducer (such as `adminOnlyReducers`, or an M-of-N multisig governance module) and your database's own rules, migrations, and permissions evolve deterministically at exact points in authored history — and rewind cleanly during suffix replay! Or omit a reducer for `$reducers` at genesis to freeze the laws of physics for the lifetime of the log.
- **Permissions, keys, finality, and UI are just topics:**
  - `$permissions` isn't hardcoded into the engine — it's a topic reducer answering a minimal capability query interface (`ctx.query('$permissions', { check: 'writer', actor })`). Ship with host-attested `attestedMembers`, zero-host M-of-N `multisigMembers`, public `openMembers`, or write your own capability system in 40 lines of JS.
  - `$keys` manages HPKE (X25519 + AES-256-GCM) epoch key lockboxes and key rotation.
  - `$finality` holds the log's time-scoped finality schedule.
  - `$publications` holds signed static web app release manifests referencing public CAS hashes.
- **Strict blind-host partition:** On private logs (`privateLog: true`), `$*` control topics are mutated *only* by `visibility: 'public'` operations and can read *only* `$*` topics and public CAS. Private application topics are mutated *only* by `visibility: 'encrypted'` operations. A completely blind host (like a Cloudflare Worker with zero decryption keys) runs the exact same `TopicKernel` in `blindHostMode: true` and derives bit-for-bit identical control state (`$reducers`, `$permissions`, `$keys`, `$finality`, `$publications`) as every full replica.

---

## 3. Chronolog-DB: A Full Vanilla SQL Database as a CRDT

Because undo-do-redo applies to *any* pure reducer over Merkle-DAG CAS, **a complete, real SQL database (`chronolog-db`) is just one standard topic reducer (`chronolog/sql`)**.

Under the hood, `chronolog-db` (`packages/sqlite-cas`) compiles **stock SQLite + FTS5 full-text search + `sqlite-vec` vector search** to a single static 1.34 MB `sqlite-cas.wasm` binary backed by a 4 KiB Merkle-paged `CAS` VFS:

- **A whole SQL database is one 32-byte hash:** The topic state stores `{ dbRoot, schemaVersion, policies, allowUserDdl }`. Every `db.commit()` writes only dirty 4 KiB pages into CAS and returns the new 32-byte `dbRoot`. Rolling back a failed transaction or rewinding to replay an earlier offline operation across a `CREATE TABLE`, `ALTER TABLE`, `UNIQUE` constraint, foreign key, FTS5 index, or `sqlite-vec` table is **O(1)** — simply open the previous `dbRoot`.
- **Multiple independent SQL databases in one log:** Bind `inventory`, `analytics`, and `scratch` to `chronolog/sql` in the same chronolog to get three isolated, hash-addressed relational databases sharing one identity, encryption, and permission boundary.
- **Bit-for-bit deterministic everywhere:** Works identically in Chromium, WebKit, Node.js, and Cloudflare Workers. `random()` and `randomblob()` are disabled; `datetime('now')` and `localtime` are pinned to the signed operation's UTC `op_time()`; read-only `PRAGMA page_size` / `PRAGMA data_version` are permitted in `mode: 'user'` so FTS5 and `sqlite-vec` (`vec0`) writes work directly in user transactions; and `actor()`, `op_id()`, and `op_time()` are bound directly in the host kernel so reducers and SQL queries can never forge the caller.

---

## 4. Declarative SQL Preconditions & Malleable Write RLS

Turning SQL into a local-first CRDT raises two real questions:
1. *What happens when an offline operation replays against a different state than the author originally saw?*
2. *How do untrusted or semi-trusted peers collaborate on shared tables without freezing the schema in concrete?*

Chronolog answers both natively inside `chronolog/sql` and `chronolog/rls`:

### Atomic Preconditions & Postconditions

Every `chronolog/sql` transaction accepts declarative `preconditions` and `postconditions` — read-only SQL assertions evaluated immediately before and after the transaction's statements:

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

If **any** precondition, postcondition, SQL constraint, or RLS trigger fails, the transaction is deterministically rejected with its exact `code` and rolled back atomically (`dbRoot` stays untouched). Two peers concurrently claiming the last task or spending the same balance both succeed optimistically offline, and on convergence the canonical `(authorTimestampMs, author, opId)` order deterministically accepts the first and rejects the second — without losing the rejected operation's original signed intent or timestamp.

### Malleable Postgres-Style Write RLS + User-Owned Dynamic DDL

Instead of static, bureaucratic permission catalogs, `chronolog/sql` pairs SQLite's C-level authorizer (`mode: 'admin' | 'user' | 'readonly'`) with `chronolog/rls` (`applyRls`):

- **Arbitrary read-only SQL write policies:** Administrators declare per-table `insert`, `update`, and `delete` predicates using `NEW.*`, `OLD.*`, `actor()`, `op_id()`, `op_time()`, and arbitrary subqueries against any table in the database (for example, checking a `grants` or `memberships` table!). Each predicate is validated through SQLite's `mode: 'readonly'` authorizer before `chronolog/rls` compiles it into tamper-proof `BEFORE INSERT/UPDATE/DELETE` triggers that `mode: 'user'` cannot alter or drop.
- **Policies evolve in the log:** Install or rewrite RLS policies at any time through ordinary signed `action: 'migrate'` or `action: 'setRls'` operations.
- **Dynamic tables for non-admin users:** With `allowUserDdl: true`, regular writers in `mode: 'user'` can `CREATE TABLE`, `ALTER TABLE`, `DROP TABLE`, `CREATE INDEX`, and `CREATE VIEW` on tables they created (tracked in `_rls_table_owners`), while remaining strictly fenced out of admin tables and other users' DDL.
- **Live schema introspection:** Query `{ query: 'schema' }` on any `chronolog/sql` topic to inspect every table, view, column list, table owner, and active RLS policy from the current deterministic snapshot.

---

## 5. A Consensus-Agnostic Core: A-la-Carte from Pure CRDT to Blockchain

Chronolog deliberately separates **state transition & ordering** from **finality & inclusion**:

- **Ordering is never decided by consensus.** `(authorTimestampMs, author, opId)` is always total and canonical.
- **Finality is an optional, pluggable, time-scoped schedule** living in the `$finality` topic.

Because the core reducer and Merkle-DAG CAS are completely consensus-agnostic, you choose *a-la-carte* how your application runs — and can even transition between modes over time (`none -> P1 -> P2`) while keeping the exact same `stateRoot` and `revision.digest`:

| Mode | `$finality` Policy | What You Get |
| --- | --- | --- |
| **Pure CRDT** | `none` | Zero coordinators, zero consensus, pure local-first peer sync. Every operation is immediately live and always revisable if earlier offline work arrives. |
| **Mostly-CRDT + Finality** | `signed-frontier` or `fixed-validator` | Collaborate offline at full CRDT speed while a trusted notary or M-of-N validator set periodically seals `closedThroughMs` checkpoints. History up to the frontier becomes irreversible; late operations claiming an already-closed timestamp are deterministically excluded (while retaining their original signed record). |
| **Blockchain-Anchored** | `blockchain-anchor` | Anchor checkpoints and inclusion proofs to an external blockchain — gaining blockchain-grade finality and checkpoint-plus-suffix fast bootstrap over the exact same SQL/JS reducer model. |

Authority (`$permissions`) is just as modular: choose `openMembers`, host-attested `attestedMembers`, zero-host M-of-N `multisigMembers`, or your own custom reducer.

---

## Architecture at a Glance

```text
Signed Operations (flat set sorted by authorTimestampMs, author, opId)
        │
        ▼
  TopicKernel (TS) ──► QuickJS-NG WASM Sandbox (Import Map in $reducers)
        │                     │
        │                     ├── chronolog/sql       (declarative SQL + preconditions/postconditions + RLS)
        │                     ├── chronolog:sqlite    (sqlite-cas.wasm: SQLite + FTS5 + sqlite-vec on 4 KiB Merkle CAS)
        │                     ├── chronolog:crypto    (sha256, verifyEd25519, canonicalJson)
        │                     ├── chronolog:cas       (explicit-link put/get)
        │                     └── chronolog/{permissions,keys,finality,publications,rls}
        ▼
  ContentAddressedStore (CAS) ──► BytesStore (Memory | IndexedDB / OPFS | Node 22+ node:sqlite)
```

### Seven Audited Standard Modules

Chronolog ships seven small, audited ES Modules pinned into public CAS at genesis:

| Module | Topic / Role | What It Does |
| --- | --- | --- |
| `chronolog/permissions` | `$permissions`, `$reducers`, `$signal_policy` | Pluggable authority presets (`attestedMembers`, `multisigMembers`, `openMembers` with `blockAuthor`/`unblockAuthor` moderation) returning a unified `{ summary: true }` permissions shape and answering capability queries (`{ check, actor }`, `{ list }`, `{ admission: true }`), admin-only `$reducers` upgrades, and ephemeral signal policy. |
| `chronolog/keys` | `$keys` | HPKE (X25519 + AES-256-GCM) epoch key lockboxes, key rotation, and fresh-device historical epoch grants (`grantBoxes`). |
| `chronolog/finality` | `$finality` | Time-scoped optional finality schedule (`none`, `signed-frontier`, `fixed-validator`, `blockchain-anchor`) with clean `none -> P1` bootstrap and `P1 -> P2` handoffs. |
| `chronolog/publications` | `$publications` | Signed static UI release manifests referencing public CAS hashes. |
| `chronolog/rls` | Utility library | Postgres-style write RLS triggers validated via SQLite's `mode: 'readonly'` authorizer (`applyRls`) plus dynamic user-table ownership helpers. |
| `chronolog/sql` | Any SQL topic(s) | First-class deterministic SQLite-CAS topic reducer (`migrate`, `setRls`, `setConfig`, `exec` with atomic preconditions/postconditions + rollback, user-owned dynamic DDL, `query({ sql, params, format })`, `schema`, and `describe()`). |
| `chronolog/sqlite-helpers` | Custom SQLite reducers | Zero-boilerplate helpers (`defineSqlReducer`, `withDb`, `rowsToObjects`) for custom `chronolog:sqlite` ES Module reducers with automatic schema/table/SQL query introspection. |

---

## Quick Example

Bind any topic directly to `chronolog/sql` (or drop in your own ES Module reducer in `imports`) — zero native builds, zero custom reducer boilerplate:

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

// 1. Ordinary signed DDL migration + malleable Postgres-style write RLS
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

// 2. Declarative transaction with atomic preconditions & automatic rollback
await (await session.submit({
  updates: [{
    topic: 'tasks',
    input: {
      preconditions: [
        { sql: 'SELECT COUNT(*) = 0 FROM tasks WHERE id = ?', params: ['t1'], code: 'already_exists' },
      ],
      statements: [
        { sql: 'INSERT INTO tasks (id, owner, title) VALUES (?, actor(), ?)', params: ['t1', 'Ship Chronolog'] },
      ],
    },
  }],
})).materialized()

// 3. Deterministic read-only SQL query + live schema/RLS introspection
console.log((await session.query('tasks', { sql: 'SELECT id, owner, title FROM tasks ORDER BY id', format: 'objects' })).value)
console.log((await session.query('tasks', { query: 'schema' })).value)
await session.close()
```

---

## Zero Native Builds

Chronolog requires **Node.js >= 22.15** and has **zero `node-gyp` / C++ native dependencies**:

- **Node durable storage:** Node's built-in `node:sqlite` (`DatabaseSync`) on one pooled worker thread per process.
- **Browser durable storage:** IndexedDB and OPFS (`OpfsBytesStore`).
- **Sandboxed ES Module reducers:** QuickJS-NG WASM (`quickjs-emscripten-core` + `@jitl/quickjs-ng-wasmfile-release-sync`).
- **Deterministic SQL:** Stock SQLite + FTS5 + `sqlite-vec` compiled to static `sqlite-cas.wasm` (compatible with Node, browsers, and Cloudflare Workers via static `WebAssembly.Module` imports).

## Workspace Commands

```sh
pnpm install --frozen-lockfile
pnpm lint && pnpm typecheck && pnpm test && pnpm build && pnpm docs:check
pnpm package:authority   # Portable @chronolog/authority tarball
pnpm package:session     # Universal zero-native-build @chronolog/peer-session tarball
```

## Documentation

- [Chronolog CRDT Contract](docs/CRDT_CONTRACT.md) — core invariants, ordering, partitioning, encryption, finality, and deterministic SQLite profile.
- [Authored Operation-Set Model](docs/authored-operation-set.md) — operation lifecycle, offline authoring, reconnect rewrapping, and checkpoint bootstrap.
- [Browser Storage Architecture](docs/browser-storage.md) — OPFS, IndexedDB, and worker ownership.
- [Documentation Index](docs/README.md) — package guides (`@chronolog/peer-session`, `@chronolog/materializer`, `chronolog-db`, `@chronolog/authority`, `@chronolog/signals`, `@chronolog/transport-webrtc`).
