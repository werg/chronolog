# Working with Chronolog

Chronolog is the local-first deterministic undo-do-redo runtime for Tendriller and standalone peer applications: Ed25519/X25519 identity, flat timestamp-ordered operation sets, pure Merkle-DAG `CAS` (`ContentAddressedStore`), QuickJS-NG Import-Map ES Module reducers (`TopicKernel`), deterministic Merkle-paged SQLite+FTS5+`sqlite-vec` (`chronolog-db`), reactive views (`createLiveView`), local view stores (`createViewStore`), encrypted device checkpoints, durable event forwarding (`forwardSessionEvents`), scoped tools (`createScopedApplicationTools`), ephemeral signals (`@chronolog/signals`), and direct/relayed replication.

## Architectural Invariants

Read [the Chronolog v2 CRDT contract](docs/CRDT_CONTRACT.md).

- **Flat timestamp-ordered operation set:** Every replica derives the exact same order from `(authorTimestampMs, author, opId)`. No peer, host, finalizer, transport receipt, or selected history assigns operation order.
- **Pure Merkle-DAG CAS & strict two-way partition:** On `privateLog: true`, `$*` control topics (`$reducers`, `$permissions`, `$keys`, `$finality`, `$publications`, `$signal_policy`, `$mounts`, `$builders`) are mutated ONLY by `visibility: 'public'` ops (which can read only `$*` topics and public CAS). Private topics are mutated ONLY by `visibility: 'encrypted'` ops. Idempotency is scoped by `(visibility, author, operationId)`. Blind hosts (`blindHostMode: true` / `replayBlindHostControl`) derive identical control state to full replicas.
- **Deterministic QuickJS-NG + Pure WASM + SQLite-CAS:** Fresh `QuickJSContext` per `reduce()`/`query()`/`describe()` invocation with 2-arg scoped `chronolog-pkg/v1` resolution, per-package `builtins` attenuation, deterministic fuel metering (`limits.maxFuel`), non-deterministic globals stripped, uncatchable host-level `MissingDependencyError` interrupts, pure deterministic `WasmSandbox` (`chronolog:wasm` + `runtime: 'wasm-pure'`), and static `WebAssembly.Module` injection for Cloudflare Workers. SQLite-CAS binds `actor()`, `op_id()`, `op_time()` in the host kernel, disables `random()`/`randomblob()`, pins `datetime('now')` and `localtime` to UTC `op_time()`, and enforces `mode: 'admin' | 'user' | 'readonly'` + `chronolog/rls`.
- **Offline authoring & reconnect rewrapping:** Author locally and durably before network delivery. Encrypted envelopes are reconciled by `encryptedEnvelopeDigest` so rewrapped offline operations sync cleanly past undecryptable older epochs while preserving original `opId`, `authorTimestampMs`, and signature.
- **Optional finality:** `finality: none` is a complete supported mode. `$finality` holds a time-scoped schedule supporting `none -> P1` bootstrap, `P1 -> P2` handoffs, and checkpoint-plus-suffix bootstrap with identical `stateRoot` and `revision.digest`.
- **Zero native C/C++ builds:** Node durable storage uses Node 22+ built-in `node:sqlite` (`DatabaseSync`). No `better-sqlite3`, no `@dolthub/doltlite`, no `node-gyp`.

## Quick Commands

```sh
pnpm install --frozen-lockfile
pnpm lint && pnpm typecheck && pnpm test && pnpm build && pnpm docs:check
pnpm test:fast            # Serial full zero-native-build suite
pnpm package:authority    # Portable @chronolog/authority tarball
pnpm package:session      # Universal zero-native-build @chronolog/peer-session tarball
node tools/package-peer-session.mjs --no-native-rtc # Relay-only tarball (no werift)
```

## Package Boundaries

- `packages/canonical`, `packages/crypto`, `packages/protocol`: deterministic CBOR, Ed25519/X25519/HPKE/AES-GCM, synchronous `@noble/ed25519`, v2 Genesis/Operation/Envelope wire formats.
- `packages/records`: `BytesStore` (`MemoryBytesStore`, `NativeBytesStore` via built-in `node:sqlite`, `IndexedDbBytesStore`), `ContentAddressedStore` (Merkle-DAG CAS with public/private partitions and exact mark-and-sweep GC), framed peer channels.
- `packages/authority`: portable signed records, canonical `ApplicationDescription` input schemas, time-scoped `$finality` verification (`verifyFinalityV2`), and `signHostAttestationV2`. Zero eager materializer/SQL/Node imports.
- `packages/materializer`: `TopicKernel` (O(changed) `state/v3`), `QuickJsSandbox` (`quickjs-emscripten-core` + `@jitl/quickjs-ng-wasmfile-release-sync`, scoped `chronolog-pkg/v1` loader, lazy `readTopic`, deterministic fuel), `WasmSandbox` (`chronolog-wasm/v1`), `evaluateDerivation` + Ed25519 attestations, and audited `STANDARD_MODULE_SOURCES` (`chronolog/{permissions,keys,finality,publications,mounts,builders,registry,rls,sql,sqlite-helpers,crdt,text,ledger,workflow,fs}`).
- `packages/sqlite-cas`: stock SQLite + FTS5 + `sqlite-vec` compiled to static `sqlite-cas.wasm` over a 4 KiB Merkle-paged `CAS` VFS with 3-mode authorizer and deterministic UTC profile.
- `packages/signals`: ephemeral signed live-lane messages with optional `stateRoot`/`supersedesStream` anchoring.
- `packages/peer-session`: unified `ApplicationSession`, `createLogGenesis`, `createRegistryGenesis`, `ApplicationDevice`, `ApplicationSessionOwner` / `WorkerApplicationSession`, `/kernel` (`replayBlindHostControl`, `collectControlReferencedCasHashes`, `dryRunReducerUpgrade`), `/mirror` (WinterCG `createCasMirrorHandler`, `createCasMirrorClient`), blueprints, reactive views, encrypted checkpoints, event forwarder, and scoped tools. Passive browser/worker/index entrypoints never eagerly load durable storage, QuickJS, or SQLite-CAS (verified by `tools/package-peer-session.mjs`).
- `packages/pack`: deterministic esbuild reducer packer, determinism linter, npm/JSR tarball ingester, lockfile, and registry client.

## Verification Rules

- Always run `pnpm lint && pnpm typecheck && pnpm test && pnpm build && pnpm docs:check` before committing.
- Never commit dirty provenance archives into downstream repos (`tendriller` requires `dirty: false` in `provenance.json`).
- Keep `pnpm docs:check` green when modifying any Markdown file.
