# 03 — Bugs, Shortcomings & Operational Risks

> **Historical evidence, not current guidance.** This review describes commit `680b70b` and the former selected-generation, coordinator-ordered architecture (`peer-generation`, `applied()`/`shared()`, recovery, takeover and handover). That architecture has been replaced by the [authored operation-set contract](../CRDT_CONTRACT.md); see the [architecture overview](../authored-operation-set.md). Its findings, status table and verification results are preserved unchanged as history. They are not a qualification of the current implementation, and its file references and fixes may no longer exist.

## Implementation status

The findings below describe the reviewed implementation before these fixes.

| Item | Status |
| --- | --- |
| 1.1 | Fixed: byte-array checkpoints use optional caller budgets instead of fixed store-size/entry caps. `exportDeviceCheckpointStream` / `restoreDeviceCheckpointStream` support large handoffs with bounded encrypted frames, sink backpressure, and optional streaming SQL. A 264 MiB handoff is covered by a regression test. |
| 1.2 | Fixed: persist the retirement marker before fencing the source in memory. |
| 1.3 | Fixed: mark the initial view captured only after `readView()` resolves. Recovery after capture still requires review. |
| 1.4 | Removed abandoned-operation truncation. `unknownLoss` remains conservative: a signed handover request can adopt an older prefix, so the handover reason alone does not prove the absence of unseen work. A lossless classification needs additional protocol evidence. |
| 1.5 | Fixed: retention checks verify local ciphertext hashes without decrypting; `retain()` signs after its verified read without a second full pass. |
| 2.1 | Fixed: coverage waits use a direct selected receipt-root lookup. |
| 2.2 | Fixed: indexed ancestry checks avoid repeated selected-history walks; verified suffixes reuse prior verification. Registry selections append signed records behind a small atomic head, with legacy-bundle migration and exact retry after lost acknowledgments. Peer hello/state exchanges send compact summaries and missing signed suffixes; full bundles remain available as a compatibility mode or when no common prefix is available. |
| 2.3 | Fixed: startup prefetches bounded batches and reuses small device-keyed HMAC attestations to skip repeated origin/receipt signature verification. Original persisted bytes are still read and hashed; stale/corrupt caches fall back to full verification. Each attempt/body/core is shared across internal indexes. `verificationCache: false` forces a full audit. Reading and decoding the retained history remains linear, as required to check original storage integrity without compaction. |
| 2.4 | Fixed: the stable `better-sqlite3` binding and prepared statements run in a dedicated worker. Acquisition, reads, writes, enumeration, WAL checkpointing and close are asynchronous. Await `NativeBytesStore.open()` and `close()`; the existing SQLite file/table format is preserved. |
| 2.5 | Open: history compaction and snapshot truncation require protocol and recovery design. |
| 3.1 | Fixed: new passphrase exports use PBKDF2-SHA256 with 600,000 iterations and authenticated, bounded algorithm/work-factor parameters. Legacy 100,000-iteration checkpoints remain readable. Raw-key exports retain their existing layout. |
| 3.2 | Open: reducing the native patch requires upstream/library work. |
| 3.3 | Fixed: neither storage adapter imports experimental `node:sqlite`. The WASM VFS uses prebuilt OS file-lock bindings on the database inode and creates no owner sidecar. Old owner sidecars require offline removal after stopping older runtimes; opening refuses these legacy markers to prevent overlapping old/new fencing protocols. |
| 3.4 | Fixed: `iterateEntries()` reads IndexedDB in bounded pages under the storage mutation queue; consumer backpressure and early iterator release are supported. Streamed restore stages envelopes on disk and publishes them in one transaction only after the authenticated input completes. The compatibility `entries()` array API necessarily retains its returned array; streaming checkpoint APIs bypass it. |

New PBKDF2 exports use the [OWASP PBKDF2-HMAC-SHA256 work factor](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#pbkdf2).

## 1. Functional Bugs

### 1.1 Checkpoint export quota is smaller than replica storage quota
- **Where:** `packages/peer-session/src/checkpoint.ts:54-56, 179-189` vs. `packages/peer-generation/src/control-types.ts` (`PEER_MAX_RECORDS = 4096`, `PEER_MAX_HISTORY_BYTES = 64 MiB`) and `packages/peer-session/src/content.ts` (`MAX_CONTENT_BYTES = 128 MiB`).
- **Bug:** `exportDeviceCheckpoint()` encodes all `BytesStore` entries as JSON + Base64 (~33% expansion) under a hard cap of **4,096 keys**, **16 MiB raw**, and **32 MiB encrypted**. A valid replica with 1,500 commands already writes >4,500 keys (`journal/N`, `record/gen/N`, `result/id`, plus heads/metadata/projections/content chunks) and can hold up to 64 MiB of history + 128 MiB of content.
- **Impact:** Any moderately used, completely within-quota device will fail `CHECKPOINT_LIMIT_EXCEEDED` when attempting device handoff/migration.

### 1.2 `retireDeviceStore()` fences in-memory state before durable retirement write succeeds
- **Where:** `packages/peer-session/src/checkpoint.ts:211-215`.
- **Bug:** `retireDeviceStore(store)` marks the store retired in memory *before* `await store.put(DEVICE_RETIRED_KEY, ...)` completes.
- **Impact:** If the `put()` fails (e.g., quota/I/O error), the store is permanently fenced in memory for the lifetime of the process even though the on-disk store was not retired.

### 1.3 Spurious `EVENT_FORWARDER_REVIEW_RECOVERY` on initial read
- **Where:** `packages/peer-session/src/event-forwarder.ts:51-62`.
- **Bug:** `captured = true` is set *before* `session.readView()` resolves, while a background loop checks `if (next.value.kind === 'recovery' && (cursor !== undefined || captured))`.
- **Impact:** If a generation recovery occurs while the very first `readView()` is pending (with `cursor === undefined`, zero events ever read or delivered), the forwarder aborts with `EVENT_FORWARDER_REVIEW_RECOVERY` instead of simply starting from the recovered view.

### 1.4 `RecoveryNotice` hardcodes `unknownLoss: true` and silently truncates `abandoned`
- **Where:** `packages/peer-generation/src/replica.ts:290-296`.
- **Bug:** `#finishRecovery()` always emits `unknownLoss: true`—even for a clean, coordinated `handover` where the successor held the exact complete prefix—and slices `abandoned` to `1024` entries without any truncation indicator.
- **Impact:** Downstream UIs and forwarders cannot distinguish a lossless planned handover from an uncoordinated takeover with potential data loss, and abandoned operations beyond 1,024 are silently omitted from the notice.

### 1.5 `ApplicationContent.retained()` re-decrypts the entire file on every call
- **Where:** `packages/peer-session/src/content.ts:127-136`.
- **Bug:** Calling `retained(reference)` loops through every 64 KiB chunk, fetches it, verifies SHA-256, and AES-GCM decrypts up to 128 MiB synchronously in a single RPC call, and `retain()` calls `retained()` *immediately after* `read()` already decrypted and verified every chunk.
- **Impact:** Doubles CPU/I/O cost on `retain()` (2x full decryption of up to 128 MiB) and risks tripping peer RPC timeouts on large blobs.

## 2. Performance & Scaling Traps

### 2.1 `waitForCoverage()` clones the entire selected history on every change event
- **Where:** `packages/peer-session/src/application-data.ts:186-197`.
- **Problem:** On every replica notification while a caller awaits `op.shared()`, `waitForCoverage` calls `await this.#replica.exportCommands()`—which `structuredClone`s and encodes up to 4,096 commands (up to 64 MiB)—just to `.find()` one `attemptId` and read its `receipt.root`.
- **Fix:** Expose a direct O(1) lookup (e.g. `replica.receiptRoot(attemptId)` or include `root` on `AppliedResult`).

### 2.2 O(G²) cloning during `PeerAuthority.verify()` and uncompacted `AuthorityBundle`
- **Where:** `packages/peer-generation/src/control.ts:182-225`.
- **Problem:** `PeerAuthority.verify()` allocates `new PeerAuthority({ ..., controls: slice, generations: slice })`—which calls `structuredClone(bundle)`—on every generation in the loop. With up to 4,096 generations allowed, verification scales quadratically. Moreover, the full `AuthorityBundle` is sent on every peer `hello` handshake and rewritten in full on every `GenerationRegistry.select()`.

### 2.3 Cold-start O(N) full re-verification & redundant in-memory copies in `Replica`
- **Where:** `packages/peer-generation/src/replica.ts:103-147, 204-239`.
- **Problem:** `Replica.initialize()` sequentially reads, CBOR-decodes, AES-GCM-decrypts, and Ed25519-verifies every journal entry and every ordered record across all generations on every reopen, and keeps redundant `structuredClone`d copies across `#records`, `#attempts`, `#receipts`, and `#selected`. `#retain()` also calls `encodePeerValue(attempt)` twice in the same check (`replica.ts:209`).

### 2.4 Unprepared SQLite statements in `NativeBytesStore`
- **Where:** `packages/records/src/native.ts:57-83`.
- **Problem:** Every `get()` and `put()` calls `this.#database.prepare(...)` fresh instead of reusing cached prepared statements, and runs synchronous `DatabaseSync` operations on the main Node event loop inside `async` methods.

### 2.5 No history compaction or snapshot truncation
- **Where:** `packages/peer-generation/src/control-types.ts` (`PEER_MAX_RECORDS = 4096`, `PEER_MAX_HISTORY_BYTES = 64 MiB`).
- **Problem:** Recovery always replays from genesis, and `controls`/`generations` also cap at 4,096. Long-lived applications inevitably hit `PEER_STORAGE_QUOTA` or `PEER_AUTHORITY_LIMIT` and stop accepting writes.

## 3. Security, Durability & Maintenance Risks

### 3.1 Weak PBKDF2 iteration count in `checkpoint.ts`
- **Where:** `packages/peer-session/src/checkpoint.ts:51`.
- **Issue:** `PBKDF2_ITERATIONS = 100_000` for passphrase-encrypted device checkpoints (containing Ed25519 signing keys and epoch keys) is well below current OWASP recommendations (600,000 for PBKDF2-SHA256) and lacks an algorithm/iteration parameter in the wire header for future upgrades.

### 3.2 Heavy native patch burden on `@dolthub/doltlite`
- **Where:** `patches/@dolthub__doltlite@0.11.29.patch` (1,326 lines across 12 files, including C++ addon sources `addon.cpp`, `database.cpp`, `statement.cpp`, `binding.gyp`, and install scripts).
- **Risk:** Tightly pins the native SQL engine to a single DoltLite version and creates high maintenance risk across Node N-API and DoltLite updates.

### 3.3 Experimental `node:sqlite` dependency & leaked sidecar lock files
- **Where:** `packages/records/src/native.ts`, `packages/materializer-doltlite/src/wasm-node.ts:206-214`.
- **Issue:** Relies on Node's experimental `node:sqlite` (`ExperimentalWarning` emitted during tests). In `wasm-node.ts`, opening a WASM SQLite file creates a `<db>.chronolog-owner.sqlite` sidecar database solely for OS-level exclusive locking and never unlinks it on close.

### 3.4 `IndexedDbBytesStore` `getAll()` / `getAllKeys()` memory spike on `entries()`
- **Where:** `packages/records/src/indexeddb-bytes-store.ts:89-106`.
- **Issue:** `entries()` loads the entire object store into memory in one transaction before decoding and verifying envelopes, which can spike browser Worker memory on large stores during checkpoint export.
