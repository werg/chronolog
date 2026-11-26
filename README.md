# Chronolog-DB

**A local-first Merkle-DAG CRDT database where your application logic, permissions, SQL tables, and UI live as hash-pinned ES Modules over a flat timestamp-ordered operation set — with zero native C/C++ builds.**

Chronolog-DB lets browsers, Node.js agents, and blind edge hosts (such as Cloudflare Workers) collaborate offline-first and converge deterministically to the exact same state, without a central sequencing server or a blockchain consensus requirement.

## The Big Idea

Most collaborative databases force an awkward choice: either centralize ordering on a server, freeze your schema and permissions in rigid database catalogs, or fight custom CRDT data structures for every feature.

Chronolog-DB takes a much simpler, composable approach built on four ideas:

1. **A Flat Timestamp-Ordered Operation Set ("Block Soup", Not Hash-Linked Blocks)**
   Every mutation is an immutable, Ed25519-signed operation carrying `(authorTimestampMs, author, opId)`. There are no `parents` pointers and no forks to merge. Every replica sorts the set of known operations by `(authorTimestampMs, author, opId)` and folds them deterministically. Late earlier operations trigger a clean suffix replay from the nearest cached Merkle snapshot.

2. **One Pure Content-Addressed Merkle-DAG (`CAS`)**
   All large state — ES Module source code, SQLite database pages, binary assets, and replay metadata — lives in one content-addressed DAG (`ContentAddressedStore`) with explicit links, public/private partition isolation, LRU caching, and exact mark-and-sweep garbage collection.

3. **One Global Reducer Calling Hash-Pinned ES Module Topic Reducers (`$reducers` Import Map)**
   From a global perspective, Chronolog is a single deterministic reducer whose state is a map of topics. One of those topics (`$reducers`) maps each topic name to a hash-pinned ES Module (`cas:sha256-...`) executed in QuickJS-NG:
   - **Self-evolving or frozen:** Bind `$reducers` to a governance reducer (such as `adminOnlyReducers`) for governed upgrades, or omit it to permanently freeze rules for the lifetime of the chain.
   - **Fresh `QuickJSContext` per invocation:** Zero module-state leaks across `reduce()`, `query()`, or suffix replay; `Date`, `Math.random`, and `Intl` are stripped; reducers read cross-topic capabilities via partition-enforced `ctx.query(topic, input)`.
   - **Pluggable permissions & authority:** `$permissions` is just another topic reducer answering a clean capability query interface (`{ check, actor }`, `{ list }`, `{ admission: true }`). Ship with `attestedMembers` (host-attested roles), `multisigMembers` (M-of-N threshold quorum with zero host attestation), `openMembers` (open public writers), or plug in your own custom `$permissions` reducer without host or runtime assumptions.
   - **Strict blind-host partition:** On private chains, `$*` control topics (`$reducers`, `$permissions`, `$keys`, `$finality`, `$publications`, `$signal_policy`) are mutated only by `visibility: 'public'` operations and can read/query only `$*` topics and public CAS. A blind Cloudflare Worker host with zero decryption keys derives the exact same control state as every full replica.

4. **First-Class Declarative SQL Topic Reducer (`chronolog/sql`) + `chronolog:sqlite` + Write RLS (`chronolog/rls`)**
   Bind any topic — or multiple topics for multiple independent hash-addressed databases in one chain — directly to `chronolog/sql` (`sqlite-cas.wasm`, 1.34 MB: stock SQLite + FTS5 + `sqlite-vec` over a 4 KiB Merkle-paged `CAS` VFS):
   - **Declarative SQL transactions with atomic preconditions & rollback:** Submit `{ preconditions, statements, mode, events }` directly; if any precondition, constraint, or RLS trigger fails, the entire transaction rolls back atomically.
   - **O(1) rollback & time travel:** A database snapshot is a single 32-byte `dbRoot` hash stored as a topic value.
   - **Deterministic across timezones and platforms:** `random()`/`randomblob()` are disabled, `datetime('now')` and `localtime` are pinned to the signed operation's UTC `op_time()`, and `actor()`, `op_id()`, `op_time()` are bound by the host kernel.
   - **Nimble Postgres-style write RLS + dynamic tables:** No rigid static schemas or bureaucratic catalogs. `chronolog/sql` uses `mode: 'admin' | 'user' | 'readonly'` + `chronolog/rls` (`applyRls`) to install validated `BEFORE INSERT/UPDATE/DELETE` triggers using arbitrary read-only SQL predicates, and safely lets non-admin users `CREATE TABLE` / `ALTER TABLE` / `DROP TABLE` on their own tables.

```text
Signed Operations (flat set sorted by authorTimestampMs, author, opId)
        │
        ▼
  TopicKernel (TS) ──► QuickJS-NG WASM Sandbox (Import Map in $reducers)
        │                     │
        │                     ├── chronolog/sql       (first-class declarative SQL + preconditions + RLS reducer)
        │                     ├── chronolog:sqlite    (sqlite-cas.wasm: SQLite + FTS5 + sqlite-vec on Merkle-paged CAS)
        │                     ├── chronolog:crypto    (sha256, verifyEd25519, canonicalJson)
        │                     ├── chronolog:cas       (explicit-link put/get)
        │                     └── chronolog/{permissions,keys,finality,publications,rls}
        ▼
  ContentAddressedStore (CAS) ──► BytesStore (Memory | IndexedDB | Node 22+ built-in node:sqlite)
```

## Six Audited Standard Modules

Chronolog ships six small, audited ES Modules pinned into public CAS at genesis:

| Module | Topic / Role | What It Does |
| --- | --- | --- |
| `chronolog/permissions` | `$permissions`, `$reducers`, `$signal_policy` | Pluggable authority presets (`attestedMembers`, `multisigMembers`, `openMembers`) answering capability queries (`{ check, actor }`, `{ list }`, `{ admission: true }`), admin-only `$reducers` upgrades, and ephemeral signal rules. |
| `chronolog/keys` | `$keys` | HPKE (X25519 + AES-256-GCM) epoch key lockboxes, key rotation, and fresh-device historical epoch grants (`grantBoxes`). |
| `chronolog/finality` | `$finality` | Time-scoped optional finality schedule (`none`, `signed-frontier`, `fixed-validator`, `blockchain-anchor`) with clean `none -> P1` bootstrap and `P1 -> P2` handoffs. Finality decides inclusion and closed author-time, never order. |
| `chronolog/publications` | `$publications` | Signed static UI release manifests referencing public CAS hashes. |
| `chronolog/rls` | Utility library | Postgres-style write RLS triggers validated through SQLite's `mode: 'readonly'` parser (`applyRls`) plus dynamic user-table ownership helpers. |
| `chronolog/sql` | Any SQL topic(s) | First-class declarative SQLite-CAS topic reducer (`migrate`, `setRls`, `exec` with atomic preconditions + rollback, user-owned dynamic table DDL, `query({ sql, params })`, and `describe()`). |

## Quick Example

Bind any topic directly to `chronolog/sql` — zero custom reducer boilerplate needed:

```ts
import { createChainGenesis, createApplicationSession } from '@chronolog/peer-session'
import { openNativeDevice } from '@chronolog/peer-session/native'

const device = await openNativeDevice({ path: './app.sqlite', create: true })
const created = await createChainGenesis({
  creator: { publicKey: device.identity.publicKey, wrapKey: device.wrapKey.publicKey, reader: true, writer: true, administrator: true },
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

await (await session.submit({
  updates: [{
    topic: 'tasks',
    input: {
      action: 'migrate',
      statements: ['CREATE TABLE tasks (id TEXT PRIMARY KEY, owner TEXT NOT NULL, title TEXT NOT NULL)'],
      policies: {
        tasks: {
          insert: 'NEW.owner = actor()',
          update: 'OLD.owner = actor() AND NEW.owner = actor()',
          delete: 'OLD.owner = actor()',
        },
      },
    },
  }],
})).materialized()

await (await session.submit({
  updates: [{
    topic: 'tasks',
    input: {
      preconditions: [{ sql: "SELECT COUNT(*) = 0 FROM tasks WHERE id = ?", params: ['t1'], code: 'already_exists' }],
      statements: [{ sql: 'INSERT INTO tasks (id, owner, title) VALUES (?, actor(), ?)', params: ['t1', 'Try Chronolog v2'] }],
    },
  }],
})).materialized()

console.log((await session.query('tasks', { sql: 'SELECT id, owner, title FROM tasks ORDER BY id', format: 'objects' })).value)
await session.close()
```

## Zero Native Builds

Chronolog-DB requires **Node.js >= 22.15** and has **zero `node-gyp` / C++ native dependencies**:
- Node durable storage uses Node's built-in `node:sqlite` (`DatabaseSync`) on one pooled worker thread per process.
- Browser storage uses IndexedDB / OPFS.
- Reducer execution uses QuickJS-NG WASM (`quickjs-emscripten-core` + `@jitl/quickjs-ng-wasmfile-release-sync`).
- Deterministic SQL uses stock SQLite + FTS5 + `sqlite-vec` compiled to static `sqlite-cas.wasm` (compatible with Node, browsers, and Cloudflare Workers via static `WebAssembly.Module` imports).

## Workspace Commands

```sh
pnpm install --frozen-lockfile
pnpm lint && pnpm typecheck && pnpm test && pnpm build && pnpm docs:check
pnpm package:authority   # Portable @chronolog/authority tarball
pnpm package:session     # Universal zero-native-build @chronolog/peer-session tarball
```

## Documentation

- [Chronolog v2 CRDT Contract](docs/CRDT_CONTRACT.md) — core invariants, ordering, partitioning, encryption, finality, and deterministic SQLite profile.
- [Authored Operation-Set Model](docs/authored-operation-set.md) — operation lifecycle, offline authoring, reconnect rewrapping, and checkpoint bootstrap.
- [Browser Storage Architecture](docs/browser-storage.md) — OPFS, IndexedDB, and worker ownership.
- [Documentation Index](docs/README.md) — package guides (`@chronolog/peer-session`, `@chronolog/materializer`, `@chronolog/sqlite-cas`, `@chronolog/authority`, `@chronolog/signals`, `@chronolog/transport-webrtc`).
