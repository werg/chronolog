# Browser record storage and compatibility

Chronolog's browser **events-only** application session keeps the same signed
application definition, command/event history, replication and recovery protocol
regardless of its local byte-record backend. This document covers **records**,
not the optional SQL materializer's separate SQLite/OPFS VFS.

## On-demand records and immutable backend identity

The dedicated Worker initially opens only the small IndexedDB metadata database
`chronolog-metadata:<name>`. Its signer, durable-device identity and verified
control remain independent of the application records. Reading status and
capabilities, creating a protocol session, receiving live signals, or inspecting
publication metadata must leave `status.database === 'idle'`.

Only the first durable operation acquires the exclusive
`chronolog:<name>` Web Lock and selects a record store:

- A persisted `peer-session/storage-backend/v1` pin chooses **only** `opfs` or
  `indexeddb`. It is versioned and immutable for that named device.
- Without a pin, a pre-existing `peer-session/storage-opened/v1` metadata
  record or even a legacy `chronolog-<name>` OPFS directory selects OPFS. If
  the old location cannot be inspected, fail closed rather than starting empty.
- For genuinely new storage, a scratch file must complete
  `createWritable()`, write, close and read-back before selecting OPFS.
  If this operation is missing or explicitly unsupported, a separate
  `chronolog-data:<name>` IndexedDB bytes database can be selected after a
  completed write/reopen probe.
- The backend pin is written before any application-record write. An error,
  missing data or capability change never triggers a silent backend switch.

`STORAGE_BINDING` remains inside the selected record backend, and
`STORAGE_OPENED` remains in metadata. The existing application-device binding
guards verify both. No page-owned signer, backend migration, new profile, storage
reset, or memory-backed durability fallback is introduced.

Both durable stores share a bounded versioned CBOR value envelope containing
the logical key, payload and SHA-256 digest. IndexedDB replaces one key in a
single readwrite transaction, requesting `durability: 'strict'`, and reports
success only on `transaction.oncomplete`. OPFS reports success after the
writer's close completes. Neither API can guarantee survival of sudden physical
power loss; a strict durability hint does not prove disk-level persistence.
Storage quotas, site-data eviction, browser-specific background Worker
suspension and private-browsing restrictions still apply.

## Explicit Worker-side capability diagnostics

The owning Worker entry exposes an **explicit** diagnostic:

```ts
import { probeBrowserCapabilities } from '@chronolog/peer-session/worker'

const report = await probeBrowserCapabilities()
console.log(report.events.supported, report.events.backend, report.events.reason)
console.log(report.sql.apiEligible, report.sql.qualified, report.sql.reason)
```

It performs representative native WebCrypto Ed25519/X25519 operations, a
scratch-only IndexedDB write/close/reopen, and scratch-only OPFS writable and
Worker sync-handle probes. It also reports secure-context, dedicated-Worker,
Web Locks and WebAssembly prerequisites. It does **not** open the device's
signer/data databases, acquire its real named lock, write a backend pin, install
an SQL engine or change `status.database`. An eligibility report is not proof
that an existing device's **pinned** backend remains accessible, or that its
record history is present.

SQL `qualified` remains false: `createSyncAccessHandle()` availability is
only a prerequisite. Applications whose signed definition requires SQL must
still install and qualify the complete DoltLite WASM engine and separate OPFS
SAH-pool VFS; there is **no** silent downgrade to events-only.

## Supported versus qualified browsers

| Environment | New events record backend | Evidence / limitation |
| --- | --- | --- |
| Current Chromium desktop | OPFS if the actual probe succeeds | Browser Worker regression included in the independent qualification workflow |
| Current Chrome for Android | OPFS if the actual probe succeeds | Physical-device write/reopen not yet qualified by this change |
| Safari 17 / iPadOS 17 | The event path requires native X25519, documented by WebKit starting in Safari 18.4 | Treat Safari 17 as unsupported for this path unless a physical browser passes the native crypto probe and the full event round trip |
| Current Safari / iPadOS | Determined by actual OPFS probe, otherwise eligible IndexedDB | No version-only assumptions or physical-device claim |
| Missing native Ed25519/X25519 or Web Locks | None | Explicitly unsupported; no silent crypto or lock fallback |
| Browser SQL/WASM | Independent of record backend | Unqualified on Safari 17 until the complete engine/VFS is tested |

Desktop Playwright WebKit is useful regression evidence, but **does not** qualify
real iPadOS 17 Safari. [WebKit documents native X25519 in Safari 18.4.](https://webkit.org/blog/16574/webkit-features-in-safari-18-4/) Qualify an actual iPad before stating Safari 17
application-level support. Browser storage persistence must also be tested
across Worker termination and page reload with the shipped artifacts.

## Failure handling and development gates

- `BROWSER_STORAGE_IN_USE`: a different Worker owns the exclusive named data lock.
- `BROWSER_STORAGE_BACKEND_UNSUPPORTED`: the pinned or proposed backend cannot
  run; retaining the device identity takes precedence over starting empty.
- `BROWSER_STORAGE_BACKEND_AMBIGUOUS`: the state of an old/interrupted OPFS
  installation could not be safely distinguished from new storage.
- `BROWSER_STORAGE_BACKEND_PIN_INVALID`: backend metadata is corrupt or
  has an unrecognized version; do not overwrite the pin.
- `APPLICATION_DATA_STORAGE_MISSING` and
  `APPLICATION_DATA_STORAGE_BINDING_INVALID`: the existing device-binding
  checks remain authoritative after selecting a backend.
- IndexedDB `INDEXEDDB_TRANSACTION_ABORTED`, blocked connections, corruption,
  quota exceptions or OPFS writer errors remain real failures, **not** a
  reason to activate the other backend.

Run `pnpm lint && pnpm typecheck && pnpm test && pnpm build && pnpm docs:check`
and the real Chromium test `pnpm exec tsx tools/test-browser-storage.ts`.
The independent application workflow also qualifies packed-session Chromium
Worker/RTC and matched Tendriller consumer artifacts. The complete Safari 17
events-only round trip, old-build interrupted-write behavior, long-term storage
quota/performance, and SQL coexistence each require additional real-device/fault
qualification before a wider support claim. Preserve per-repository commit
SHAs, artifact digests and actual browser versions in the qualification record.
