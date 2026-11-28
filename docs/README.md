# Chronolog-DB Documentation

- [Chronolog CRDT Contract](CRDT_CONTRACT.md) — formal invariants for ordering, public/encrypted partitioning, QuickJS-NG Import-Map reducers, deterministic SQLite-CAS, write RLS, keys, finality, and signals.
- [Unified CAS, Packages, Derivations & Registry](PACKAGES_AND_DERIVATIONS.md) — `chronolog-blob/v1`, `chronolog-enc-blob/v1`, `chronolog-pkg/v1`, `chronolog-drv/v1`, scoped QuickJS/WASM runtimes, `$mounts`, `$builders`, `@chronolog/pack`, and the dogfooded Registry Chronolog.
- [Authored Operation-Set Guide](authored-operation-set.md) — practical guide to authoring, replication, reconnect rewrapping, checkpoints, and reactive views.
- [Browser Storage Architecture](browser-storage.md) — OPFS, IndexedDB, and single-owner worker isolation in browsers.

## Package Guides

- [`@chronolog/peer-session`](../packages/peer-session/README.md) — full session API, `createLogGenesis`, `ApplicationDevice`, `ApplicationSessionOwner`, `createLiveView`, `forwardSessionEvents`, and `createScopedApplicationTools`.
- [`@chronolog/materializer`](../packages/materializer/README.md) — `TopicKernel`, `QuickJsSandbox`, and the 5 audited standard ES Modules.
- [`chronolog-db`](../packages/sqlite-cas/README.md) — Merkle-paged SQLite + FTS5 + `sqlite-vec` WASM SQL database driver and deterministic profile.
- [`@chronolog/authority`](../packages/authority/README.md) — portable signed records, `ApplicationDescription`, and time-scoped `$finality` verification.
- [`@chronolog/signals`](../packages/signals/README.md) — signed ephemeral live-lane messages.
- [`@chronolog/transport-webrtc`](../packages/transport-webrtc/README.md) — direct WebRTC data-channel and media/stream transport.
