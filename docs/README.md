# Chronolog Documentation

- [Chronolog CRDT Contract](CRDT_CONTRACT.md) — formal invariants for ordering, O(changed) `state/v3`, public/encrypted partitioning, scoped QuickJS-NG & pure WASM reducers, deterministic SQLite-CAS, write RLS, keys, finality, mounts, builders, and signals.
- [Unified CAS, Packages, Derivations & Registry](PACKAGES_AND_DERIVATIONS.md) — `chronolog-blob/v1`, `chronolog-enc-blob/v1`, `chronolog-pkg/v1`, `chronolog-tree/v1`, `chronolog-drv/v1`, scoped QuickJS/WASM runtimes, `$mounts`, `$builders`, WinterCG HTTP CAS mirrors, `@chronolog/pack`, and the dogfooded Registry Chronolog.
- [Authored Operation-Set Guide](authored-operation-set.md) — practical guide to authoring, replication, reconnect rewrapping, checkpoints, and reactive views.
- [Browser Storage Architecture](browser-storage.md) — OPFS, IndexedDB, and single-owner worker isolation in browsers.
- [Performance](PERFORMANCE.md) — `sync-v3` reconciliation protocol, O(changed) kernel cost model, and the `pnpm bench` harness.

## Package Guides

- [`@chronolog/peer-session`](../packages/peer-session/README.md) — full session API, `createLogGenesis`, `createRegistryGenesis`, `/kernel` (`replayBlindHostControl`, `collectControlReferencedCasHashes`, `dryRunReducerUpgrade`), `/mirror` (`createCasMirrorHandler`, `createCasMirrorClient`), blueprints, reactive views, and worker ownership.
- [`@chronolog/materializer`](../packages/materializer/README.md) — `TopicKernel`, `QuickJsSandbox`, `WasmSandbox`, `evaluateDerivation`, attestations, and the audited standard ES Modules.
- [`chronolog-db`](../packages/sqlite-cas/README.md) — Merkle-paged SQLite + FTS5 + `sqlite-vec` WASM SQL database driver and deterministic profile.
- [`@chronolog/authority`](../packages/authority/README.md) — portable signed records, `ApplicationDescription`, and time-scoped `$finality` verification.
- [`@chronolog/signals`](../packages/signals/README.md) — signed ephemeral live-lane messages.
- [`@chronolog/transport-webrtc`](../packages/transport-webrtc/README.md) — direct WebRTC data-channel and media/stream transport.
