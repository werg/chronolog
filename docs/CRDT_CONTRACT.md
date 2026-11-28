# Chronolog CRDT Contract

## 1. Core Model: Flat Timestamp-Ordered Operation Set

A Chronolog chain is identified by `logId = hashDomain('genesis', encodeLogGenesis(genesis))`.

All state is deterministically derived by folding a **flat set** of signed operations (no `parents` hash-links) sorted strictly by the canonical comparator:

```text
(authorTimestampMs ASC, authorPublicKeyBytes ASC, opIdBytes ASC)
```

No peer, host, relay, finalizer, transport receipt, or selected branch may assign operation order. Late arrival of an earlier operation triggers a deterministic suffix replay from the nearest cached snapshot.

## 2. Two-Way Public/Encrypted Control Partition

On chains with `privateLog: true`:
- Control topics (`$reducers`, `$admission`, `$seals`, `$keys`, `$publications`, `$mounts`, `$builders`) may ONLY be mutated by `visibility: 'public'` operations.
- Public operations can ONLY read `$*` topics and `public` CAS nodes.
- Application (non-`$`) topics may ONLY be mutated by `visibility: 'encrypted'` operations (wrapped in `EncryptedOperationEnvelope` under an epoch key).
- Idempotency deduplication is scoped by `(visibility, author, operationId)`. The consumed-key set is a deterministic function of the ordered history (committed by `historyDigest`) and is committed as a `seenOpsRoot` CAS node whenever state is exported (materialized cache, snapshot bundle, checkpoint bootstrap).

**Guarantee:** A blind host (`blindHostMode: true`) that holds zero decryption keys and replays only public operations derives bit-for-bit identical `$*` control topic state to every full replica, even under adversarial cross-partition `(author, operationId)` collisions.

## 3. Hash-Pinned Packages, Scoped Import Maps & Pure WASM (`$reducers`)

`$reducers` defines:
- `runtime`: pinned JS engine (`quickjs-ng@0.32.0`) and builtins (`chronolog:crypto`, `chronolog:cas`, `chronolog:sqlite`, `chronolog:wasm`).
- `imports`: map of bare module specifiers to `cas:sha256-<64-hex>` hashes in CAS (either single-file leaf modules or `chronolog-pkg/v1` Merkle-DAG packages).
- `topics`: map of topic names to `{ module, export?, config? }` (accepting either an import alias or a direct `cas:sha256-<64-hex>` reference).

Execution invariants:
- Fresh `QuickJSContext` per `reduce()`, `query()`, `describe()`, `onConflict()`, and `derive()` invocation (zero cross-call state leakage).
- Non-deterministic globals (`Date`, `performance`, `Math.random`, `Intl`) are removed (contexts are created without the Date intrinsic, which in quickjs-ng also supplies the `performance` clock), and deterministic fuel metering (`limits.maxFuel`) rejects runaway loops uniformly as `vm:fuel_exhausted`.
- `chronolog-pkg/v1` packages enforce scoped dependency resolution (eliminating diamond conflicts), package-local `./`/`../` relative imports, and per-package `builtins` capability attenuation.
- Pure WASM reducers (`runtime: 'wasm-pure'`, `chronolog-wasm/v1` ABI) and `chronolog:wasm` libraries reject non-`chronolog` host imports and cache compiled `WebAssembly.Module` instances per `cas:sha256-...` hash.
- Missing CAS chunks, modules, packages, or SQLite pages trigger an **uncatchable host-level `MissingDependencyError`** that user JS `try/catch` cannot swallow; replay halts cleanly before that operation until the missing dependency arrives (via `cas-want` subgraph pull or `casMirrors`).
- Historical `$reducers` package hashes remain pinned in `TopicKernel.gcRoots()` across the active replay window so late-arriving ops and `materializeAt()` time-travel survive GC.
- If `$reducers` has no topic binding for `"$reducers"`, rules are permanently frozen.
- External Chronolog logs are never live-queried; cross-log state is composed deterministically via pinned signed snapshots in `$mounts` (`ctx.mount()` / `ctx.mountQuery()`).

## 4. State Root, Rolling History Digest & Revision Identity

After each operation:
- `topicHash(t) = hashDomain('topic', canonicalCbor(topics[t]))`, recomputed only for topics the operation changed
- `stateRoot = hashDomain('state', cbor({ [topic]: topicHash }))` (state domain `chronolog/state/v3`)
- `historyDigest = hashDomain('history', cbor([prevHistoryDigest, opId, outcome, rejectionCode, canonicalEvents]))`
- `revision.digest = hashDomain('revision', cbor([historyDigest, stateRoot, view, policyContextDigest]))`

Checkpoints and snapshots carry `topics`, `seenOpsRoot` and `historyDigest`; restoring them and replaying the suffix produces the exact same `stateRoot` AND `revision.digest` as a cold replay from genesis. Per-operation cost is O(changed state), not O(history): no per-op seen-set node, no whole-state clone, no whole-map state hash.

## 5. Keys, Hybrid Post-Quantum HPKE, Anonymous Envelopes & Reconnect Rewrapping (`$keys`)

- Each device holds a persistent Ed25519 signing identity, a persistent X25519 `wrapKey`, and a persistent hybrid post-quantum X-Wing (`ML-KEM-768 + X25519`) `pqWrapKey`.
- `$keys` stores per-epoch `suite` (`hpke-x25519-aes256gcm` or hybrid PQ `hpke-xwing-aes256gcm`), `keyCommitment`, one-way derived `mailboxVerifyKey`, write-once per-member HPKE lockboxes, compartment `rings`/`topicRings` (enforced fail-closed by `TopicKernel`), and on-log `$keys.policy` (`rotateOnRemove`, `maxOpsPerEpoch`, `minSuite`, `paddingBucketBytes`, `hideEnvelopeAuthor`).
- Encrypted envelopes use 192-bit HKDF-SHA256 per-operation AES-256-GCM subkeys (`hkdf-aes-256-gcm`) with optional power-of-2 bucket padding. When `hideEnvelopeAuthor` is enabled, outer `envelope.author` is zeroed (`ANONYMOUS_AUTHOR`) and authenticated via `mailboxTag` signed by the epoch's derived Ed25519 mailbox key so blind hosts reject unauthorized uploads without learning writer identity or payload length.
- Admitting a fresh device on a chain with rotated epochs atomically updates `$admission` and grants HPKE lockboxes for retained historical epochs (`grantBoxes`) so the fresh device can decrypt and replay history. Members can self-rotate wrap keys via `$admission.rotateWrapKey` and seal selective per-recipient payloads via `session.sealFor()` / `session.unseal()`.
- Encrypted envelopes are reconciled by `encryptedEnvelopeDigest` (not `opId` alone). When an offline device reconnects after an epoch rotation, it re-encrypts its exact original signed operation bytes under the newest epoch while preserving `opId`, `authorTimestampMs`, and signature.
- Under `open` history admission, membership and key grants are provisional until all earlier operations are known; post-revocation confidentiality applies to epochs rotated after revocation whose ciphertext is not distributed to revoked peers. See [Sub-Linear Group Key Rotation Design Brief](SUBLINEAR_GROUP_ROTATION.md) for the planned `O(log N)` tree-based `$keys` upgrade.

## 6. Deterministic SQLite-CAS Profile & Write RLS (`chronolog:sqlite`, `chronolog/rls`)

`chronolog:sqlite` runs stock SQLite + FTS5 + `sqlite-vec` on a 4 KiB Merkle-paged `CAS` VFS (64-way fanout):
- `actor()`, `op_id()`, and `op_time()` are bound directly by the host kernel per operation.
- `random()` and `randomblob()` are disabled; `datetime('now')` and `localtime` modifiers resolve deterministically to UTC `op_time()`; `changes()` and `last_insert_rowid()` reset at every `openDb()` boundary.
- `PRAGMA recursive_triggers = ON` is always active.
- Three execution modes enforced by SQLite's C authorizer:
  - `mode: 'admin'` — DDL, DML, and trigger management (trusted reducer logic).
  - `mode: 'user'` — DML (`INSERT`/`UPDATE`/`DELETE`/`SELECT`) plus optional `ddl` allowlist (`createTable`, `alterTable`, `dropTable`, `indexOn`, `createView`, `dropView`). Never allowed to touch `_*` internal tables or `_rls_*` triggers.
  - `mode: 'readonly'` — pure `SELECT` queries and `validateExpr()`.
- `chronolog/rls` (`applyRls`) validates every user write predicate through SQLite's `mode: 'readonly'` parser (forbidding semicolons, sub-writes, and injection) before wrapping it in `BEFORE INSERT/UPDATE/DELETE` triggers with `RAISE(ABORT, ...)`.

## 7. Unified Admission (`$admission`) & Kernel-Enforced Immutability (`$seals`)

`$admission` unifies four concerns in one state-defined module:
1. **Per-operation fail-closed authorization (`authorize(state, tx, ctx)`):** Invoked automatically by `TopicKernel` before any non-`$admission` topic reducer runs; local topic reducers can only monotonically tighten, never weaken global admission.
2. **Optional semantic post-conditions (`verify(before, after, tx, ctx)`):** Pure, flat post-execution invariant check over `before`/`after` topic snapshots; failure rolls back the entire atomic multi-topic transaction.
3. **Consensus-agnostic history admission (`admit(state, { logId, ops, evidence, pinnedFrontier }, ctx)`):** Evaluates time-scoped `schedule` policies (`open`, `signed-frontier`, `threshold-quorum`, `member-quorum`, `optimistic-challenge`, `merkle-anchor`, `pinned-checkpoint`) and locally pinned non-rewinding frontiers (`pinnedFrontier`) identically on full peers and blind hosts. Operations with `authorTimestampMs <= closedThroughMs` absent from `includedOpIds` are deterministically excluded.
4. **Ephemeral signal authorization (`query('$admission', { kind: 'signals' })`):** Cached per `stateRoot` so membership revocations take effect immediately on `@chronolog/signals` live lanes.

`$seals` is a plain-data, kernel-enforced monotonic ratchet table (`{ reducers, paths }`):
- Existing seals can never be removed or weakened (`append-only` may tighten to `frozen`, never reverse), enforced directly by `TopicKernel` before every commit.
- `reducers[topic] = true` pins the topic's resolved `(moduleRef, export, config)` (including resolved `$reducers.imports` CAS hashes).
- `paths[topic][dotPath] = 'frozen' | 'append-only'` locks a JSON subtree forever (auto-sealing `reducers[topic]` by default unless `allowMutableReducer: true` is specified).
