# Chronolog v2 CRDT Contract

## 1. Core Model: Flat Timestamp-Ordered Operation Set

A Chronolog chain is identified by `chainId = hashDomain('genesis', encodeGenesisBlock(genesis))`.

All state is deterministically derived by folding a **flat set** of signed operations (no `parents` hash-links) sorted strictly by the canonical comparator:

```text
(authorTimestampMs ASC, authorPublicKeyBytes ASC, opIdBytes ASC)
```

No peer, host, relay, finalizer, transport receipt, or selected branch may assign operation order. Late arrival of an earlier operation triggers a deterministic suffix replay from the nearest cached snapshot.

## 2. Two-Way Public/Encrypted Control Partition

On chains with `privateChain: true`:
- Control topics (`$reducers`, `$permissions`, `$keys`, `$finality`, `$publications`, `$signal_policy`) may ONLY be mutated by `visibility: 'public'` operations.
- Public operations can ONLY read `$*` topics and `public` CAS nodes.
- Application (non-`$`) topics may ONLY be mutated by `visibility: 'encrypted'` operations (wrapped in `EncryptedOperationEnvelope` under an epoch key).
- Idempotency deduplication is scoped by `(visibility, author, operationId)` and authenticated in `seenOpsRoot` (stored in CAS).

**Guarantee:** A blind host (`blindHostMode: true`) that holds zero decryption keys and replays only public operations derives bit-for-bit identical `$*` control topic state to every full replica, even under adversarial cross-partition `(author, operationId)` collisions.

## 3. Hash-Pinned Import-Map Reducers (`$reducers`)

`$reducers` defines:
- `runtime`: pinned JS engine (`quickjs-ng@0.32.0`) and builtins (`chronolog:crypto`, `chronolog:cas`, `chronolog:sqlite`).
- `imports`: map of bare module specifiers to `cas:sha256-<64-hex>` hashes in CAS.
- `topics`: map of topic names to `{ module, export?, config? }`.

Execution invariants:
- Fresh `QuickJSContext` per `reduce()`, `query()`, and `describe()` invocation (zero cross-call state leakage).
- Non-deterministic globals (`Date`, `Math.random`, `Intl`) are removed.
- Missing CAS chunks, modules, or SQLite pages trigger an **uncatchable host-level `MissingDependencyError`** that user JS `try/catch` cannot swallow; replay halts cleanly before that operation until the missing dependency arrives.
- If `$reducers` has no topic binding for `"$reducers"`, rules are permanently frozen.

## 4. State Root, Rolling History Digest & Revision Identity

After each operation:
- `stateRoot = hashDomain('state', cbor({ seenOpsRoot, topics }))`
- `historyDigest = hashDomain('history', cbor([prevHistoryDigest, opId, outcome, rejectionCode, canonicalEvents]))`
- `revision.digest = hashDomain('revision', cbor([historyDigest, stateRoot, view, policyContextDigest]))`

Committing to `seenOpsRoot` and `historyDigest` ensures that checkpoint bootstrap plus suffix replay produces the exact same `stateRoot` AND `revision.digest` as a cold replay from genesis.

## 5. Keys, Rotation & Reconnect Rewrapping (`$keys`)

- Each device holds a persistent Ed25519 signing identity and a persistent X25519 `wrapKey`.
- `$keys` stores per-epoch `keyCommitment` and HPKE (`DHKEM(X25519,HKDF-SHA256)/HKDF-SHA256/AES-256-GCM`) lockboxes per authorized reader.
- Admitting a fresh device on a chain with rotated epochs atomically updates `$permissions` and grants HPKE lockboxes for retained historical epochs (`grantBoxes`) so the fresh device can decrypt and replay history.
- Encrypted envelopes are reconciled by `encryptedEnvelopeDigest` (not `opId` alone). When an offline device reconnects after an epoch rotation, it re-encrypts its exact original signed operation bytes under the newest epoch while preserving `opId`, `authorTimestampMs`, and signature.
- Under `finality: none`, membership and key grants are provisional until all earlier operations are known; post-revocation confidentiality applies to epochs rotated after revocation whose ciphertext is not distributed to revoked peers.

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

## 7. Optional Time-Scoped Finality (`$finality`)

`$finality` stores a strictly monotonic schedule `[{ effectiveAfterMs, policy }]`.
- `policy.kind = 'none'` is a first-class supported mode (zero finality dependencies; finalized-only reads explicitly reject with `FINALITY_UNSUPPORTED`).
- Supported finalizing policies: `signed-frontier`, `fixed-validator`, and `blockchain-anchor`.
- Handoff rule at `effectiveAfterMs = T1`:
  - Outgoing finalizing policy `P0` must seal through `>= T1` before `P1` checkpoints are accepted.
  - When `P0` is `'none'`, `P1` attests its bootstrap frontier at `>= T1` directly.
- Finality checkpoints commit to `closedThroughMs`, `includedSetDigest`, `historyDigest`, `stateRoot`, and `inclusions`. Operations with `authorTimestampMs <= closedThroughMs` absent from `includedOpIds` are deterministically excluded.

## 8. Ephemeral Signals (`@chronolog/signals` & `$signal_policy`)

Ephemeral live-lane messages (cursors, typing, streaming tokens) stay completely off the durable operation set. `SignalStream` carries optional `stateRoot` and `supersedesStream` anchoring, and `ApplicationSession` caches `$signal_policy` per `stateRoot` so membership revocations take effect immediately.
