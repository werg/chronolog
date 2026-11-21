# Chronolog

Chronolog is an owned, peer-to-peer application session for browser Workers and Node.js peers. One eligible peer orders commands per generation; every peer verifies original authorship, selected order, and the execution contract before materializing state locally.

## Core model

- **Signed command journal**: `command()` durably stores one signed, encrypted attempt before dispatch. Retrying preserves the original bytes and operation identity.
- **Explicit outcomes**: `applied()` resolves with acceptance or rejection at a `(generation, sequence)`. `shared()` observes independent peer retention.
- **Coherent views**: `query()` and `readView()` expose consistent SQL, events, outcomes, and revision. Recovery switches all of them together.
- **Replaceable coordination**: Signed control transitions select a successor coordinator and adopt a verified prefix. Excluded work stays inspectable and requires explicit reapplication.
- **Monotonic authority**: Reader, writer, coordinator, recovery, administration, and publication grants are explicit and never roll back with data recovery.
- **Unified session**: Live ephemeral signals and encrypted chunked content share the same identity, authorization, and lifetime.
- **Transport independence**: Direct WebRTC and WebSocket relay share one framed, authenticated, encrypted channel. Control services participate only in authority, discovery, and signed code publication—never application payloads.

## Quick start

See the [session reference](packages/peer-session/README.md) for the complete API.

```ts
import { openNativeApplication, openNativeDevice } from '@chronolog/peer-session/native'

const session = await openNativeApplication({ device, definition, authority })
const control = session.connectControlParticipant({ exchange })
try {
  const before = await session.query('messages', null)
  const op = await session.command('say', { text: 'Hello' }, {
    operationId: crypto.randomUUID(),
    basedOn: before.revision,
  })
  const result = await op.applied()
  console.log(result.generation, result.sequence, result.outcome)
} finally {
  await session.close()
}
```

Native peers store data in SQLite under an exclusive writer lock; browser peers run the same session inside an owning Worker using OPFS or IndexedDB under an exclusive Web Lock.

## Packages

| Package | Responsibility |
| --- | --- |
| `peer-session` | Public session lifecycle, commands, queries, recovery, content, keys, participation, and tools |
| `peer-generation` | Signed authority, generation ordering, ancestry verification, replica replay, and publications |
| `records` | Bounded byte stores (native SQLite, browser OPFS/IndexedDB), framing, and flow-controlled channels |
| `materializer` | Execution contract and SQL-free event materializer |
| `materializer-doltlite` | Deterministic SQL execution over native and WASM DoltLite engines |
| `transport-webrtc` | Browser and native WebRTC negotiation, reliable/live channels, and HTTP introductions |
| `transport-websocket` | Dual-socket reliable/live WebSocket transport |
| `signals` | Bounded, signed ephemeral JSON signals |
| `protocol`, `crypto`, `canonical` | Deterministic CBOR, domain hashing, Ed25519/HPKE/AES-GCM, programs, and SQL validation |
| `conformance` | Cross-engine execution equivalence, crash/reopen, and soak qualification |

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
node tools/package-peer-generation-control.mjs
```

## Documentation

- [Session API reference](packages/peer-session/README.md)
- [Architecture and authority](docs/peer-generation-v1.md)
- [Deterministic SQL](docs/implementation-specs/10-deterministic-sql-transactions.md)
- [Row ownership](docs/design-owner-rows.md)
- [Sealed values](docs/sealed-data.md)
- [Browser storage](docs/browser-storage.md)
- [Qualification](docs/release-hardening.md)
