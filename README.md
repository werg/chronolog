# Chronolog

Chronolog is a **local-first, freely programmable deterministic CRDT runtime** for JavaScript, WebAssembly, and edge runtimes. It turns any deterministic state transition function—including a full relational SQLite database with FTS5 and vector search, pure WebAssembly kernels, and static web releases—into a strongly eventually consistent, end-to-end encrypted, offline-capable replicated system.

- **Freely programmable and self-bootstrapping:** The genesis operation defines the rules (code) by which subsequent operations reduce state, including the rules for evolving the rules themselves (`$reducers`), membership (`$permissions`), encryption epochs (`$keys`), finality schedules (`$finality`), static releases (`$publications`), cross-log dependencies (`$mounts`), and build trust (`$builders`).
- **One unified Merkle-DAG Content-Addressed Store (CAS):** Code packages (`chronolog-pkg/v1`), directory trees (`chronolog-tree/v1`), streaming public and encrypted blobs (`chronolog-blob/v1`, `chronolog-enc-blob/v1`), 4 KiB Merkle-paged SQLite databases (`chronolog-db`), and reproducible build derivations (`chronolog-drv/v1`) all live in one content-addressed DAG with exact mark-and-sweep GC, one-RTT subgraph pulls, and zero-trust HTTP edge mirroring.
- **Fast, deterministic execution across JS and WebAssembly:** Reducers run inside QuickJS-NG WASM with scoped package resolution, per-package capability attenuation, lazy topic reads, and deterministic fuel metering—or directly as pure deterministic WebAssembly (`chronolog:wasm` and standalone `runtime: 'wasm-pure'`).
- **Content-addressed derivations with opt-in trusted caching:** Builds and transforms are pure `CAS -> CAS` functions (`chronolog-drv/v1`). Replicas can recompute permissionlessly or skip local builds in O(1) by verifying M-of-N Ed25519 builder/auditor attestations (`chronolog-attestation/v1`) from untrusted HTTP mirrors against the log's own `$builders` policy—*you only need trust for speed*.

---

## Core Architecture

Chronolog rests on five interlocking design principles:

### 1. A Flat, Timestamp-Ordered Operation Set

A Chronolog log is modeled as an **unordered set** of standalone, Ed25519-signed operations scoped to a genesis hash (`logId`). Operations carry no parent hashes, block pointers, or causal chain links; while aggregated state is content-addressed, this is not a blockchain.

Every replica derives the exact same canonical total order solely by sorting the operations it has observed by:

```text
(authorTimestampMs ASC, authorPublicKey ASC, opId ASC)
```

No peer, relay, host, or validator assigns operation order. Replicating between peers is set reconciliation (`sync-v3` range-fingerprint reconciliation over WebRTC, WebSocket, or HTTP) plus on-demand subgraph pulls for referenced CAS hashes.

### 2. O(changed) Rollback-and-Replay over a Single Pure Merkle-DAG CAS

Building on the undo-do-redo model for replicated logs, Chronolog treats convergence as a property of deterministic reduction rather than of bespoke merge algorithms:

```text
State  = Map<TopicName, StateValue>
Kernel : (State, Operation) -> State
```

- **Offline authoring:** Devices sign and persist operations locally before any network I/O and immediately materialize them against local state.
- **O(1) rewind & O(changed) materialization (`state/v3`):** Each topic's hash is recomputed only when that topic changes (`stateRoot = hashDomain('state', cbor({ [topic]: topicHash }))`). Late earlier-timestamped arrivals rewind in O(1) to a preceding snapshot and deterministically replay only the suffix.
- **Unified CAS object model:** Every artifact in Chronolog is a canonical explicit-link `CasNode` (`hash = hashDomain('cas', cbor([bytes, sortedUniqueLinks]))`):

| Format | Purpose | Key Properties |
| --- | --- | --- |
| `chronolog-pkg/v1` | Scoped JS/WASM package | Multi-file POSIX tree, subpath `exports`, scoped `dependencies` (diamond-dependency safe), per-package `builtins` allowlist, optional `wasm` entry, optional non-GC `derivation` provenance back-link. |
| `chronolog-tree/v1` | Canonical directory tree | Sorted POSIX path -> `cas:sha256-...` map used for build inputs, static `$publications` releases (`treeRoot`), and direct HTTP tree serving. |
| `chronolog-blob/v1` | Public chunked Merkle blob | 64 KiB leaves, 64-way fanout; identical hash for small single-chunk files and huge streaming assets. |
| `chronolog-enc-blob/v1` | Encrypted chunked blob | Epoch-key AES-GCM encrypted chunks stored in `private` CAS, reconciled lazily over P2P without bloating eager sync. |
| `chronolog-drv/v1` | Reproducible build derivation | Pure `CAS -> CAS` spec (`builder` package, named `inputs`, canonical `args`, memory & fuel `limits`, `quickjs-inline` or `wasi-cas-v1` profile). |
| `chronolog-attestation/v1` | Signed build / audit receipt | Ed25519-signed claim binding `drvRef -> outputRef` (`kind: 'build'`) or `pkgRef -> approved|revoked` (`kind: 'audit'`). |

### 3. Self-Describing Kernel ("Reducer of Reducers"), Scoped Packages & Pure WASM

State is a map of named **topics**. One reserved control topic—`$reducers`—maps specifiers to hash-pinned ES modules or `chronolog-pkg/v1` packages (`cas:sha256-...`) and binds each topic to its reducer.

- **Scoped module resolution & capability attenuation:** QuickJS-NG uses a two-argument `(base, specifier)` loader resolving `pkg:<pkgHash>/<path>`, `./`/`../` relative imports, and per-package scoped `dependencies` (allowing two packages to depend on incompatible versions of a library simultaneously). Each package only receives the host builtins explicitly declared in its `builtins` allowlist (`chronolog:crypto`, `chronolog:cas`, `chronolog:sqlite`, `chronolog:wasm`).
- **Deterministic fuel & uncatchable dependency halts:** Non-deterministic globals (`Date`, `Math.random`, `Intl`) are removed, every invocation executes under a deterministic VM fuel budget (`limits.maxFuel`, default `200_000`), and missing CAS nodes trigger an uncatchable host interrupt (`MissingDependencyError`) until fetched from peers or mirrors.
- **Fast native-speed Pure WASM (`chronolog:wasm` & `runtime: 'wasm-pure'`):** Compute-heavy reducers, codecs, parsers, or layout engines can run as pure WebAssembly modules (`WasmSandbox`, cached compiled `WebAssembly.Module` per CAS hash, rejecting all non-`chronolog` host imports) either invoked from JS via `chronolog:wasm` (`invoke`/`invokeJson`) or bound directly as standalone `chronolog-wasm/v1` topic reducers without entering QuickJS at all.
- **Evolving or frozen rules:** Binding `$reducers` to `adminOnlyReducers` or `attestedReducers` lets schemas, business logic, and permissions evolve at exact points in logical history—and cleanly unwind if an earlier operation triggers suffix replay. Leaving `$reducers` unbound at genesis freezes the log's rules permanently.

### 4. Content-Addressed Derivations, `$builders` Governance & Trusted Mirror Caching

Chronolog treats builds and compilation the same way it treats state transitions—as deterministic functions over CAS:

- **Permissionless local evaluation:** `session.evaluateDerivation(drvRef)` executes a `chronolog-drv/v1` builder deterministically against CAS and permanently memoizes `drvHash -> outputHash`.
- **Per-log trust for speed (`$builders` + HTTP CAS Mirrors):** Logs can declare trusted builder keys, auditor keys, and an M-of-N threshold in `$builders` (`chronolog/builders`). When evaluating a derivation or installing a package (`attestedReducers`), replicas query untrusted HTTP mirrors (`@chronolog/peer-session/mirror`), locally re-verify M-of-N Ed25519 `chronolog-attestation/v1` signatures, and pull the verified output subgraph in a single HTTP round-trip (`GET /cas/sha256-<hash>?subgraph=1`)—skipping local compilation completely while retaining cryptographic auditability.
- **Reusable WinterCG HTTP CAS Mirror (`@chronolog/peer-session/mirror`):** Ships a zero-Node-dependency `createCasMirrorHandler()` and `createCasMirrorClient()` for Cloudflare Workers, Deno, Bun, and Node serving `/cas/:hash` (with `ETag`/`304`, `Range`/`206`, and `?subgraph=1` CBOR bundles), `/derivations/:drvHash`, `/audits/:pkgHash`, and `/trees/:treeHash/*path`.

### 5. Verified Cross-Log Mounts (`$mounts`), Dogfooded Registry & `@chronolog/pack`

- **Cross-log state composition (`$mounts`):** A log can pin a cryptographically signed snapshot of an external Chronolog log (such as a shared package registry, shared reference catalog, or team directory) into `$mounts` via `session.mountLog(name, externalSession)`. Reducers read and query mounted logs deterministically and lazily via `ctx.mount(name)` and `ctx.mountQuery(name, topic, input)`.
- **Dogfooded Package Registry (`chronolog/registry`):** Public or private package registries are themselves ordinary Chronolog logs (`createRegistryGenesis()`) backed by `chronolog:sqlite` + FTS5 full-text search, storing `chronolog-pkg/v1` releases, `chronolog-drv/v1` provenance, and signed builder/auditor attestations.
- **Developer Ergonomics (`@chronolog/pack`):** Developers write ordinary TypeScript/JavaScript and import npm/JSR packages. `@chronolog/pack` bundles dependencies deterministically via `esbuild`, runs a static determinism linter (catching `Date.now`, `Math.random`, `fetch`, etc.), ingests npm/JSR tarballs directly into `chronolog-tree/v1` CAS nodes, writes deterministic `chronolog.lock.json` lockfiles, and emits ready-to-install `chronolog-pkg/v1` DAGs.

---

## SQLite as a Replicated Topic (`chronolog-db` and `chronolog/sql`)

Because rollback-and-replay applies to any deterministic reducer over CAS, a full relational database becomes a standard topic reducer (`chronolog/sql`) rather than a bespoke replication protocol:

- **Merkle-paged SQLite + FTS5 + `sqlite-vec` in WebAssembly:** Stock SQLite compiled to static `sqlite-cas.wasm` over a 4 KiB Merkle-paged VFS. Each commit flushes only dirty 4 KiB pages into CAS and returns a 32-byte `dbRoot` hash. Rewinding across `CREATE TABLE`, `ALTER TABLE`, indexes, and triggers is an O(1) pointer swap.
- **Deterministic SQL profile & read-only Chronolog introspection:** `random()`/`randomblob()` are disabled; `datetime('now')` and `localtime` resolve to UTC `op_time()`; and the host kernel binds `actor()`, `op_id()`, `operation_id()`, `op_time()`, `tx_visibility()`, `chronolog_topic(name)`, `chronolog_topic_last_op(name)`, `chronolog_op(op_id)`, `chronolog_author_last_op([author])`, and `chronolog_topic_query(topic, input_json)` alongside three eponymous read-only virtual tables (`chronolog_tx`, `chronolog_topics`, and query-only `chronolog_history`).
- **Declarative optimistic concurrency & scoped read-set tracking (`createGuardedTx`):** Every `chronolog/sql` transaction supports read-only `preconditions` (`based_on_row`, `row_matches`, arbitrary SQL) and `postconditions`, plus kernel-level causal assumptions (`afterOps`, `requiresRejected`, `op_present`, `author_last_op`, `topic_revision`, `query_match`). Clients can use `createGuardedTx(session)` (`readRow`, `readSql`, `readQuery`, `requireOwnHistory`, `requireTopicUnchanged`, `addSqlPostcondition`) to automatically compile only the reads performed for a write into signed OCC preconditions without phantom conflicts from UI views:

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
    { "sql": "SELECT NOT EXISTS (SELECT 1 FROM bins WHERE units < 0)", "code": "negative_balance" }
  ]
}
```

- **Row-level write policies (`chronolog/rls`) and user-owned DDL:** Combines SQLite's C-level authorizer (`admin`, `user`, `readonly`) with statically validated `BEFORE INSERT/UPDATE/DELETE` triggers using `NEW.*`, `OLD.*`, `actor()`, `op_id()`, `op_time()`, and arbitrary read-only subqueries.

---

## Security, Blind Hosting, Finality & Reactive UI

- **Strict Public/Encrypted Partition & Reusable Blind Host (`@chronolog/peer-session/kernel`):** On `privateLog: true`, `$*` control topics (`$reducers`, `$permissions`, `$keys`, `$finality`, `$publications`, `$signal_policy`, `$mounts`, `$builders`) are mutated ONLY by `public` ops (which can read only `$*` topics and `public` CAS). Application topics are mutated ONLY by `encrypted` ops. Untrusted edge servers (such as Cloudflare Workers) call `replayBlindHostControl()` (`TopicKernel({ blindHostMode: true })`) with zero decryption keys and derive bit-for-bit identical control state and reachable public CAS sets (`collectControlReferencedCasHashes`).
- **End-to-End Encryption & Offline Reconnect Rewrapping (`$keys`):** Persistent Ed25519 signing + X25519 wrapping identities; HPKE (`DHKEM(X25519)/HKDF-SHA256/AES-256-GCM`) epoch lockboxes. Reconnecting offline peers re-encrypt their exact original signed operation bytes under the newest epoch—preserving original `opId`, `authorTimestampMs`, and signature.
- **Pluggable Authority (`$permissions`):** `attestedMembers` (host-attested admission + guardian M-of-N recovery), `multisigMembers` (zero-host M-of-N governance), `openMembers` (public logs with blocking/vouching), or custom reducers.
- **Consensus-Agnostic, Programmable Time-Scoped Finality (`$finality`):** Ordering is always canonical via `(authorTimestampMs, author, opId)`. Logs default to `finality: none` (pure CRDT) and can monotonically schedule `signed-frontier`, `fixed-validator`, `blockchain-anchor`, or state-defined **`predicate`** policies (`{ kind: 'predicate', module, export?, config? }`) evaluated deterministically in QuickJS-NG/WASM across full peers and blind hosts (`replayBlindHostControl`) against verifiable `evidence` attestations (weighted quorums, optimistic challenge windows, external Merkle anchors, or custom admission rules). Checkpoint-plus-suffix bootstrap produces the exact same `stateRoot` and `revision.digest`.
- **Reactive Views, Event Forwarding & Ephemeral Signals:** `createLiveView` (coherent snapshots with topic/SQL-table invalidation), `forwardSessionEvents` (with explicit retraction callbacks on suffix rewind), `createViewStore` (local drafts), and `@chronolog/signals` (signed bounded ephemeral live lane governed by `$signal_policy`).

---

## Standard Modules

Chronolog pins a suite of audited ES Modules into public CAS at genesis:

| Category | Module | Purpose |
| --- | --- | --- |
| **Control Plane** | `chronolog/permissions` | `attestedMembers`, `multisigMembers`, `openMembers`, `adminOnlyReducers`, and `defaultSignalPolicy`. |
| | `chronolog/keys` | HPKE epoch key lockboxes, epoch rotation, and historical epoch grants. |
| | `chronolog/finality` | Time-scoped finality schedule (`none`, `signed-frontier`, `fixed-validator`, `blockchain-anchor`, `predicate`). |
| | `chronolog/finality-predicates` | Programmable admission predicates (`signedFrontierPredicate`, `thresholdQuorumPredicate`, `optimisticChallengePredicate`, `merkleAnchorPredicate`). |
| | `chronolog/publications` | Signed static application releases referencing public CAS hashes and `chronolog-tree/v1` `treeRoot`. |
| | `chronolog/mounts` | `verifiedMounts` — Ed25519-signed snapshots of external Chronolog logs queryable via `ctx.mountQuery()`. |
| | `chronolog/builders` | `attestedBuilders` & `attestedReducers` — M-of-N builder/auditor governance for derivations and reducer upgrades. |
| **Relational SQL** | `chronolog/sql` | First-class SQLite-CAS topic reducer with migrations, preconditions/postconditions, write RLS, and user-owned DDL. |
| | `chronolog/rls` | Static `readonly` validation and trigger generation (`applyRls`, `stampRowOp`, `enableAuditLog`) for row-level write policies. |
| | `chronolog/sqlite-helpers` | Helpers (`defineSqlReducer`, `withDb`, `rowsToObjects`) for custom SQLite-backed reducers. |
| **Guards & Patterns** | `chronolog/guards` | Composable JS & SQL pre/post condition helpers (`guardReducer`, `requireAuthorChain`, `requireTopicVersion`, `sqlBasedOnRow`, `sqlRequireAuthorLastOp`). |
| | `chronolog/quotas` | Deterministic per-author token-bucket rate limits & quotas driven by `tx.authorTimestampMs`. |
| | `chronolog/queue` | Deterministic job queue with time-based leases, retries, and dead-letter handling. |
| | `chronolog/votes` | Weighted voting, quorum polls, and timelocked decision tallies. |
| | `chronolog/schema` | Lightweight deterministic JSON schema validation (`validate`) and versioned `migrateState`. |
| | `chronolog/audit` | Hash-chained tamper-evident audit log reducer with chain integrity verification. |
| **Data Structures** | `chronolog/crdt` | Out-of-order-safe LWW maps, sets, and counters. |
| | `chronolog/text` | RGA collaborative text editing with stable character identifiers. |
| | `chronolog/ledger` | Double-entry accounts, holds, and allowances. |
| | `chronolog/workflow` | Role-gated state machines with multi-approval transitions. |
| | `chronolog/fs` | Hierarchical path tree with deterministic conflict naming. |
| **Registry** | `chronolog/registry` | Dogfooded SQLite+FTS5 package registry storing `chronolog-pkg/v1` releases and signed attestations. |

---

## Usage

### 1. Creating and Querying a Replicated SQL Log

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
  topics: { tasks: { module: 'chronolog/sql' } },
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
        tasks: { insert: 'NEW.owner = actor()', update: 'OLD.owner = actor()', delete: 'OLD.owner = actor()' },
      },
    },
  }],
})).materialized()

const rows = await session.query('tasks', { sql: 'SELECT id, owner, title FROM tasks ORDER BY id', format: 'objects' })
console.log(rows.value)
await session.close()
```

### 2. Installing Multi-File Packages (`chronolog-pkg/v1`), Mounting External Logs, and Mirroring CAS

```ts
import { createLogGenesis, createApplicationSession, createRegistryGenesis } from '@chronolog/peer-session'
import { createCasMirrorHandler, createBytesStoreCasMirrorStore } from '@chronolog/peer-session/mirror'

// Install a scoped, capability-attenuated multi-file package directly into $reducers
await session.installPackage({
  name: 'app/inventory',
  version: '1.0.0',
  files: {
    'index.js': 'import { clamp } from "./math.js"; export default { reduce(s, tx) { return { ok: true, state: clamp((s || 0) + tx.payload.delta) }; } };',
    'math.js': 'export const clamp = n => Math.max(0, n);',
  },
  exports: { '.': 'index.js' },
  builtins: [], // zero host capabilities granted to this package
}, {
  alias: 'app/inventory',
  topics: { stock: {} },
})

// Mount a verified snapshot of an external Registry Chronolog into $mounts
await session.mountLog('registry', registrySession)

// Serve CAS subgraphs, derivation attestations, and chronolog-tree/v1 files on any WinterCG edge worker
const mirrorFetch = createCasMirrorHandler({
  store: createBytesStoreCasMirrorStore(bytesStore),
  basePath: '/_cas',
})
```

### 3. Packing TypeScript/npm Reducers with `@chronolog/pack`

```ts
import { packReducers } from '@chronolog/pack'

const bundle = await packReducers({
  entries: { 'app/planner': './src/reducers/planner.ts' },
  builtins: { 'app/planner': ['chronolog:sqlite'] },
})
// Deterministic CAS DAG ready for createLogGenesis({ bundle }) or session.installPackage(...)
```

---

## Runtime Architecture and Portability

```text
Signed Operations (flat set ordered by authorTimestampMs, author, opId)
        │
        ▼
  TopicKernel (O(changed) state/v3)
        ├──► QuickJS-NG WASM Sandbox (scoped chronolog-pkg/v1, fuel, lazy readTopic)
        │        ├── chronolog/sql        (declarative SQL, preconditions, RLS)
        │        ├── chronolog:sqlite     (SQLite + FTS5 + sqlite-vec on 4 KiB Merkle CAS)
        │        ├── chronolog:wasm       (invoke pure deterministic WASM modules)
        │        ├── chronolog:crypto     (sha256, verifyEd25519, canonicalJson)
        │        ├── chronolog:cas        (explicit-link content-addressed put/get)
        │        └── ctx.mountQuery()     (verified cross-log $mounts)
        └──► WasmSandbox (standalone runtime: 'wasm-pure', cached WebAssembly.Module)
        │
        ▼
  ContentAddressedStore (unified Merkle-DAG CAS: pkg, tree, blob, enc-blob, drv, SQLite pages)
        ├──► BytesStore (Memory | Browser OPFS/IndexedDB | Node 22+ node:sqlite)
        ├──► P2P Subgraph Sync (sync-v3 + cas-want subgraph=true over WebRTC / WebSocket)
        └──► WinterCG HTTP CAS & Derivation Mirror (@chronolog/peer-session/mirror)
```

Chronolog requires **Node.js >= 22.15** and has **zero native C/C++ build dependencies** (`node-gyp` is never used):

- **Node.js:** Durable storage runs on Node's built-in `node:sqlite` (`DatabaseSync`).
- **Browsers:** A dedicated Web Worker owns keys, storage (OPFS or IndexedDB), and reducer execution; the main thread imports a passive RPC facade (`@chronolog/peer-session/browser`) that never eagerly loads storage, QuickJS, or SQLite.
- **Edge runtimes (Cloudflare Workers):** QuickJS-NG and `sqlite-cas.wasm` accept pre-compiled `WebAssembly.Module` instances; `@chronolog/peer-session/kernel` and `@chronolog/peer-session/mirror` contain zero `node:*` imports.

### Repository Packages

| Package | Responsibility |
| --- | --- |
| `@chronolog/canonical` | Deterministic CBOR encoding, hashing, and canonical serialization. |
| `@chronolog/crypto` | Ed25519 signing/cached verification, X25519 key agreement, HPKE, and cached AES-256-GCM primitives. |
| `@chronolog/protocol` | Genesis, operation, encrypted envelope, and wire format definitions. |
| `@chronolog/records` | `BytesStore` implementations, unified Merkle-DAG `ContentAddressedStore` (`pkg`/`tree`/`blob`/`enc-blob`/`drv` codecs & subgraph traversal), and framed channels. |
| `@chronolog/authority` | Portable signed records, input schemas, and time-scoped `$finality` verification (zero runtime/SQL imports). |
| `@chronolog/materializer` | `TopicKernel` (O(changed) `state/v3`), `QuickJsSandbox` (scoped packages + fuel), `WasmSandbox` (pure WASM), `evaluateDerivation`, attestations, and all 15 standard ES modules. |
| `chronolog-db` | Deterministic SQLite + FTS5 + `sqlite-vec` WASM driver over a 4 KiB Merkle-paged CAS VFS. |
| `@chronolog/signals` | Signed, bounded ephemeral live-lane messaging. |
| `@chronolog/transport-webrtc` | Direct WebRTC data-channel and media transport with in-band negotiation. |
| `@chronolog/transport-websocket` | WebSocket framed peer channel transport. |
| `@chronolog/peer-session` | Unified `ApplicationSession`, `createLogGenesis`, `createRegistryGenesis`, `BlindHostControlEngine` (`/kernel`), WinterCG HTTP CAS Mirror (`/mirror`), blueprints, dry-run validation, reactive views, and worker ownership. |
| `@chronolog/pack` | Deterministic esbuild reducer packer, static determinism linter, npm/JSR tarball ingester, lockfile, and registry client. |

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

- [Chronolog CRDT Contract](docs/CRDT_CONTRACT.md) — formal invariants for ordering, `state/v3`, public/encrypted partitioning, QuickJS-NG & pure WASM reducers, deterministic SQLite-CAS, write RLS, keys, finality, mounts, builders, and signals.
- [Unified CAS, Packages, Derivations & Registry](docs/PACKAGES_AND_DERIVATIONS.md) — `chronolog-pkg/v1`, `chronolog-tree/v1`, `chronolog-blob/v1`, `chronolog-enc-blob/v1`, `chronolog-drv/v1`, pure WASM, `$mounts`, `$builders`, HTTP CAS mirrors, `@chronolog/pack`, and the dogfooded Registry Chronolog.
- [Authored Operation-Set Guide](docs/authored-operation-set.md) — operation lifecycle, offline authoring, reconnect rewrapping, reactive views, and checkpoint bootstrap.
- [Browser Storage Architecture](docs/browser-storage.md) — OPFS, IndexedDB, capability probing, and single-owner worker isolation.
- [Performance](docs/PERFORMANCE.md) — `sync-v3` reconciliation protocol, O(changed) kernel cost model, and the `pnpm bench` harness.
- [Documentation Index](docs/README.md) — package guides for `@chronolog/peer-session`, `@chronolog/materializer`, `chronolog-db`, `@chronolog/authority`, `@chronolog/signals`, and `@chronolog/transport-webrtc`.
