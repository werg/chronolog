# Chronolog

Chronolog is an owned, peer-to-peer application session for browser Workers and Node.js peers. The application is a CRDT of immutable, signed, encrypted proposals. Every peer independently verifies authorship, authority and the execution contract, unions the operation set, and materializes state locally in one deterministic order: `(signed authorTimestampMs, signing public key, stable proposal ID)`. No peer, server, agent, finalizer or transport assigns that order. See the [authored operation-set contract](docs/CRDT_CONTRACT.md) and the [architecture overview](docs/authored-operation-set.md).

## Core model

- **Local-first authoring**: `submit()` and `command()` sign the exact intent with one author timestamp and durably store it on this device before returning. Retry preserves the original bytes, identity and timestamp, and a changed request under the same operation ID is rejected. Success means stored locally, not delivered, executed, retained or final.
- **Revisable outcomes**: The signed intent is immutable; its provisional SQL outcome is not. An operation that arrives later but carries an earlier author time can change later outcomes, rows, effective events and schema. Missing bodies, keys or authority stay visible pending dependencies rather than becoming fake rejections.
- **Separate facts**: `stored`, `materialized` (a coherent local outcome at a revision), `retained` (signed peer availability evidence) and `finalized` (optional closed-time proof) are separate observations. `operation.inspect()` and `operation.materialized()`, `.retained()` and `.finalized()` expose them; `session.operations.get/subscribe/retry` find, watch and re-drive operations by ID.
- **Coherent views**: `query()` returns `{ applicationId, revision, value }`; `readView()` captures one immutable snapshot of SQL, events and revision. A reactive consumer derives its UI from such snapshots plus separate local drafts and invalidates when `changes()` reports revised proposals.
- **Optional finality**: The default policy is `none`, a complete mode with no finalizer. Explicit `signed-frontier` and `fixed-validator` policies add signed admission and closed-time evidence that browser, native or host finalizers can supply. A closed frontier can exclude a newly seen older proposal; the original intent stays inspectable and is never silently retimestamped.
- **Ordinary schema and permissions**: DDL, DML, ownership and permission changes are normal authorized transactions. There is no frozen application schema digest. Per-namespace and per-object DDL rights are independent of cryptographic grants, administration, finalization and code publication.
- **Authority and publication**: `@chronolog/authority` holds signed application metadata, time-windowed membership and epoch keys, finality proofs and signed code publication. These govern who can decrypt, author, finalize or publish. They never order operations or overwrite application permission state.
- **Unified session**: Live ephemeral signals and encrypted chunked content share the same identity, authorization and lifetime.
- **Transport independence**: Direct WebRTC and WebSocket relay share one framed, authenticated, encrypted channel. Transports carry and de-duplicate facts. Their receipts, arrival order and replay counters do not define application order.

## Quick start

See the [session reference](packages/peer-session/README.md) for the complete API.

```ts
import { createApplicationSession, openNativeDevice } from '@chronolog/peer-session/native'

// `create: true` only during explicit first setup; later runs resume the retained signer.
const device = await openNativeDevice({ path: './device.sqlite', create: true })
const session = await createApplicationSession({ device, definition, authority })
try {
  const op = await session.command('say', { text: 'Hello' }, { operationId: crypto.randomUUID() })
  console.log(op.inspect().stored)                 // true: signed and durable on this device
  const outcome = await op.materialized()          // accepted | rejected at this revision; revisable
  const view = await session.query('messages', null)
  console.log(outcome.outcome, view.revision.digest, view.value)
} finally {
  await session.close()
}
```

`authority` is a verified `AuthorityProvider` or `AuthorityBundle`, and `definition` is built with `defineApplication`. The session opens cached identity, authority and keys without host discovery, a peer, an agent or a finalizer. A fresh device still needs enrollment and explicit key provisioning before it can read or author.

Native peers store data in SQLite under an exclusive writer lock; browser peers run the same session inside an owning Worker using OPFS or IndexedDB under an exclusive Web Lock. That device-local lock fences a physical store. It is not application ordering.

## Packages

| Package | Responsibility |
| --- | --- |
| `peer-session` | Public session lifecycle, authored operations, queries, content, keys, provisioning, participation, finality driving and tools |
| `authority` | Portable signed application metadata, membership windows, grants, publications and optional finality proofs |
| `records` | Bounded byte stores (native SQLite, browser OPFS/IndexedDB), framing, and flow-controlled channels |
| `materializer` | Execution contract and SQL-free event materializer |
| `materializer-doltlite` | Deterministic SQL execution over native and WASM DoltLite engines |
| `transport-webrtc` | Browser and native WebRTC negotiation, reliable/live channels, and HTTP introductions |
| `transport-websocket` | Dual-socket reliable/live WebSocket transport |
| `signals` | Bounded, signed ephemeral JSON signals |
| `protocol`, `crypto`, `canonical` | Deterministic CBOR, domain hashing, Ed25519/HPKE/AES-GCM, programs, canonical transaction order, and SQL validation |
| `conformance` | Cross-engine execution equivalence, crash/reopen, and soak characterization |

## Build, test, and package

Requires Node 22+ (Node 24 for native SQLite/packaging checks) and pnpm 10:

```sh
corepack pnpm install --frozen-lockfile
corepack pnpm lint
corepack pnpm typecheck
corepack pnpm test
corepack pnpm build
corepack pnpm docs:check
```

Package clean standalone archives:

```sh
node tools/package-peer-session.mjs
node tools/package-peer-session.mjs --sql-native --output artifacts/peer-session-sql
node tools/package-peer-session.mjs --sql-browser --output artifacts/peer-session-sql-browser
node tools/package-authority.mjs
```

## Package and browser CI

The package and browser workflow builds the public session archives, installs
them in a clean consumer, and exercises Worker RTC endpoints and Chromium/WebKit
record stores. Chronolog CI tests Chronolog only; it does not check out or pin
Tendriller or its cookbooks.

## Documentation

- [Session API reference](packages/peer-session/README.md)
- [Authored operation-set contract](docs/CRDT_CONTRACT.md)
- [Architecture and authority](docs/authored-operation-set.md)
- [Deterministic SQL](docs/implementation-specs/10-deterministic-sql-transactions.md)
- [Row ownership](docs/design-owner-rows.md)
- [Sealed values](docs/sealed-data.md)
- [Browser storage](docs/browser-storage.md)
- [Qualification](docs/release-hardening.md)
