# Working with Chronolog-DB

Chronolog-DB is the central peer-session pipe for Tendriller and standalone local-first applications: signing identity, deterministic execution, storage (`BytesStore`), operation journals, reactive views (`createLiveView`), local view stores (`createViewStore`), encrypted device checkpoints (`exportDeviceCheckpoint` / `restoreDeviceCheckpoint`), durable event forwarding (`forwardSessionEvents`), scoped tools (`createScopedApplicationTools`), and direct/relayed replication.

## Quick Commands

### JS-only contributor fast lane (zero native C/C++ builds)
```sh
pnpm install --frozen-lockfile --ignore-scripts
pnpm test:fast          # Serial import-closure JS test suite (excludes tests transitively importing native SQL)
pnpm lint && pnpm typecheck && pnpm docs:check
```

### Full suite (with patched native SQL engine)
```sh
pnpm install --frozen-lockfile
pnpm lint && pnpm typecheck && pnpm test && pnpm build && pnpm docs:check
```

### Packaging public artifacts (requires clean git tree unless `--allow-dirty`)
```sh
pnpm package:control                                           # Filtered host control/publication package
pnpm package:session                                           # Default events + native WebRTC
node tools/package-peer-session.mjs --no-native-rtc            # Lean events-relay-only (no werift)
node tools/package-peer-session.mjs --no-native-rtc --sql-wasm # Portable WASM SQL relay-only
node tools/package-peer-session.mjs --sql-native --sql-browser --sql-wasm # Full SQL package
```

## Package Boundaries

- `packages/canonical`, `packages/crypto`, `packages/protocol`: deterministic CBOR, Ed25519/X25519/AES-GCM, wire formats. Zero native bindings.
- `packages/records`: `BytesStore` (`MemoryBytesStore`, `NativeBytesStore` via one pooled worker-backed `better-sqlite3` thread per process, `IndexedDbBytesStore`), framed peer channels.
- `packages/peer-generation`: `peer-generation-v1` control authority, publications, and filtered host participant (`@chronolog/peer-generation/participant`). Must stay portable (zero `node:*` imports in control/participant bundles).
- `packages/materializer` & `packages/materializer-doltlite`: event materializer (pure JS) and deterministic SQL materializer (native Node-API + browser/Node WASM adapters).
- `packages/peer-session`: unified session runtime, reactive views, view stores, encrypted checkpoints, event outbox, ergonomic batch/lifecycle client, and scoped tools. Passive browser/worker entrypoints must never eagerly load durable storage or SQL modules (verified by `tools/package-peer-session.mjs`).

## Verification Rules

- Always run `pnpm lint && pnpm typecheck && pnpm test:fast` (and `pnpm test` when touching SQL or packaging) before committing.
- Never commit dirty provenance archives into downstream repos (`tendriller` requires `dirty: false` in `provenance.json`).
- Keep `pnpm docs:check` green when modifying any Markdown file.
