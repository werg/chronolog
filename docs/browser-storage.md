# Browser record storage

Browser events-only sessions keep protocol metadata separate from durable application records and support OPFS or IndexedDB behind one immutable per-device backend pin. SQL sessions use a separate DoltLite WASM + OPFS SAH-pool VFS.

## Lazy activation and backend pinning

1. Opening a browser device reads only `chronolog-metadata:<name>` (IndexedDB) for signer identity and verified authority. Status checks, live signals, and publication reads leave `status.database === 'idle'`.
2. On first durable access, the owning Worker acquires the exclusive `chronolog:<name>` Web Lock and selects a backend once:
   - Existing `peer-session/storage-backend/v1` pin: uses the pinned `opfs` or `indexeddb` store; never switches silently.
   - New storage: probes OPFS `createWritable()` (write, close, read-back). If unsupported, probes `chronolog-data:<name>` IndexedDB. Pins the chosen backend before writing application records.
3. Both backends wrap values in a bounded, SHA-256-verified CBOR envelope. IndexedDB commits with `durability: 'strict'`; OPFS commits on `writer.close()`.

## Capability probing

Run an explicit scratch-only diagnostic inside the Worker before deciding whether to open durable state:

```ts
import { probeBrowserCapabilities } from '@chronolog/peer-session/worker'

const report = await probeBrowserCapabilities()
// report.events: { supported, backend, reason }
// report.sql: { apiEligible, qualified, reason }
```

Probing tests WebCrypto Ed25519/X25519, Web Locks, scratch IndexedDB, and scratch OPFS without touching the device's real databases or changing `status.database`.

## Browser matrix

| Environment | Events backend | Notes |
| --- | --- | --- |
| Chromium desktop | OPFS (if writable probe passes), else IndexedDB | Covered by Playwright Worker tests |
| Chrome for Android | OPFS (if writable probe passes), else IndexedDB | Physical-device verification separate |
| Safari 18.4+ / iPadOS | OPFS or IndexedDB per runtime probe | Native X25519 required (absent in Safari 17) |
| Missing Ed25519/X25519 or Web Locks | Unsupported | Fails closed with no fallback |

## Key error codes

- `BROWSER_STORAGE_IN_USE`: another Worker holds the exclusive `chronolog:<name>` lock.
- `BROWSER_STORAGE_BACKEND_UNSUPPORTED`: pinned or probed backend unavailable.
- `BROWSER_STORAGE_BACKEND_AMBIGUOUS`: conflicting unpinned OPFS/IndexedDB state detected.
- `BROWSER_STORAGE_BACKEND_PIN_INVALID`: corrupt backend pin metadata.
- `APPLICATION_DATA_STORAGE_MISSING` / `APPLICATION_DATA_STORAGE_BINDING_INVALID`: record store missing or bound to a different device/application.

Verify with `pnpm exec tsx tools/test-browser-storage.ts`.
