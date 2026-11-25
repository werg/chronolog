# Working with Chronolog-DB

Chronolog-DB is the central peer-session pipe for Tendriller and standalone local-first applications: signing identity, deterministic execution, storage (`BytesStore`), operation journals, reactive views (`createLiveView`), local view stores (`createViewStore`), encrypted device checkpoints (`exportDeviceCheckpoint` / `restoreDeviceCheckpoint`), durable event forwarding (`forwardSessionEvents`), scoped tools (`createScopedApplicationTools`), and direct/relayed replication.

## Architectural invariants

Read [the authored operation-set contract](docs/CRDT_CONTRACT.md). The application
is a CRDT of immutable, signed proposals. Every replica derives the same order
from `(authorTimestampMs, signing public key, stable proposal ID)`. No peer, agent,
server, finalizer, transport receipt or selected history may assign operation order.

Author locally and durably before network delivery; exact retry preserves original
identity, timestamp and bytes. Separate local storage, revisable materialization,
peer retention and optional finality. No finality is a complete supported mode,
not a disabled coordinator. Browser/native/host finalizers verify the same optional
admission and closed-time policy; they have no ordering/comparator interface.

Schema, grants and collective membership change through ordinary permissioned
transactions in the authored-time replay. Do not freeze application schema or
rewrite the materialized permission catalog from a latest external control head.
The engine/platform manifest pins deterministic execution, not database structure.
Preserve protected catalogs and actual namespace/object authorization.

Prefer reactive views derived from coherent snapshots. Late earlier operations
can change SQL outcomes, effective events, rows and schema; invalidate/rederive
rather than accumulating network events as UI truth. Keep local drafts separate.

This is one clean protocol. There are no generation-order APIs, migrations,
legacy readers, compatibility exports or rollback-to-another-branch execution.
Device-local owner locks and transport replay counters are not application order.

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
pnpm package:authority                                         # Portable CRDT authority/publication/finality package
pnpm package:session                                           # Default events + native WebRTC
node tools/package-peer-session.mjs --no-native-rtc            # Lean events-relay-only (no werift)
node tools/package-peer-session.mjs --no-native-rtc --sql-wasm # Portable WASM SQL relay-only
node tools/package-peer-session.mjs --sql-native --sql-browser --sql-wasm # Full SQL package
```

## Package Boundaries

- `packages/canonical`, `packages/crypto`, `packages/protocol`: deterministic CBOR, Ed25519/X25519/AES-GCM, wire formats. Zero native bindings.
- `packages/records`: `BytesStore` (`MemoryBytesStore`, `NativeBytesStore` via one pooled worker-backed `better-sqlite3` thread per process, `IndexedDbBytesStore`), framed peer channels.
- `packages/authority`: portable application/membership/publication authority and optional finality proofs/providers. Keep it free of eager native/SQL dependencies; finality never supplies the operation comparator.
- `packages/materializer` & `packages/materializer-doltlite`: event materializer (pure JS) and deterministic SQL materializer (native Node-API + browser/Node WASM adapters).
- `packages/peer-session`: unified session runtime, reactive views, view stores, encrypted checkpoints, event outbox, ergonomic batch/lifecycle client, and scoped tools. Passive browser/worker entrypoints must never eagerly load durable storage or SQL modules (verified by `tools/package-peer-session.mjs`).

## Verification Rules

- Always run `pnpm lint && pnpm typecheck && pnpm test:fast` (and `pnpm test` when touching SQL or packaging) before committing.
- Never commit dirty provenance archives into downstream repos (`tendriller` requires `dirty: false` in `provenance.json`).
- Keep `pnpm docs:check` green when modifying any Markdown file.
