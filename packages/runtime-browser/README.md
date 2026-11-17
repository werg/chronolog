# Browser peer runtime

This package runs a complete Chronolog peer in one dedicated browser Worker. The Worker owns signing and reader keys, exact signed feed records, immutable ordering evidence, durable operation state, the control index, and validator cutoffs in OPFS. A signed group chooses either the SQL/events execution profile or the SQL-free events profile. The page uses the ordinary `ChronologClient` through `WorkerRpcTransport` in either case.

The same protocol, membership, admission, history policy, materializer, SQL restrictions, enrollment service, and RPC contract run in native and browser peers. `openBrowserPeer` supplies the browser storage and engine adapters. A group chooses its peer or coordinated history policy in its signed genesis descriptor; selecting a transport does not change that policy.

In the default coordinated composition, a portable Cloudflare membership
administrator verifies compact controls committed by the native closure;
a native finality service proves inclusion and closes author time. Full browser
replicas independently recompute that control projection from complete receipts. Every browser
sorts application proposals itself with the shared chronological comparator.
Application envelopes are detached and fetched
only through reader-authorized peers. A SQL-free events peer still receives and
executes its application events, whereas the thin administrator has no application
payload-fetch port. Signed genesis separately names the roster issuer and the
initial schema administrator. Neither host login nor transport access grants an
application SQL role.

`openBrowserEventPeer`, exported from `@chronolog/runtime-browser/events`, opens
the durable event execution profile without importing or instantiating the SQL
engine. This subpath also exports `WorkerRpcTransport`. SQL calls fail explicitly;
event publication, final cursor reads/subscriptions, retained read views, and
operation retries use the same public APIs as SQL/events peers. Execution profile
selection belongs to the signed group, so an event-only node cannot silently
interpret a SQL group's history.

## Live signals and peer connections

Both governed browser profiles expose `peer.signals` and
`peer.connectPeer({ connection, peerIdentity? })`. Supply a ready framed connection,
for example `frameRtcPeerChannels({ reliable, live })` after its `ready` promise
resolves. Its independent live lane carries signals without waiting for history
credits or large body transfers. A reliable-only connection carries replication
and installs no signal route.
The runtime selects the local reader grant, verifies the remote current reader,
attaches replication and signals through the same governed service used by native
peers, and returns `{ peer, signal, completion, close }`. The session's `signal`
aborts when that exact connection ends. An optional
`peerIdentity` pins a particular endpoint in addition to its group capability.
The owning Worker retains all keys and signs outgoing messages there.

The page uses `client.signals.send(...)` and `client.signals.subscribe(...)`
through the ordinary `WorkerRpcTransport`. There is no application-specific
Worker message protocol to implement. Signals have no operation IDs, SQL,
retention, finality waits or reconnect replay. Their default subscription keeps
accepted messages in a bounded FIFO; choose `mode: 'latest'` for values replaceable
per author, session and topic. Signal rights are independent from SQL/durable
publication rights, and a read-only member can subscribe.

Connection close detaches its exact replication and signal route, including
failed attachment and late handshake completion during shutdown. Browser peer
close aborts the live channel and pending connection setup before releasing OPFS.
A low-level custom `node` composition may provide `configuration.signals` with
its own policy and explicitly configured routes. Governed composition always
derives its signal policy from active membership, and convenience `connectPeer`
requires that governance controller. The
standalone [`SignalChannel`](../signals/README.md) works without any browser peer,
OPFS store, SQL engine or database grant.

## Build and qualify

Use Node 24, pnpm 10.12.4, a C/C++ compiler, make, Python, Tcl and zlib development headers. Install the workspace dependencies first; the pinned DoltLite package builds the patched native engine and retains its checksum-verified source tree.

```sh
pnpm install --frozen-lockfile
git clone --depth 1 --branch 4.0.20 https://github.com/emscripten-core/emsdk.git /your/build/emsdk
test "$(git -C /your/build/emsdk rev-parse HEAD)" = e4fe26ef59168ff44f4c23c466e497bf60b3411e
/your/build/emsdk/emsdk install 4.0.20
/your/build/emsdk/emsdk activate 4.0.20
node tools/build-wasm-engine.mjs --emsdk /your/build/emsdk
CHRONOLOG_REQUIRE_WASM=1 pnpm exec vitest run packages/runtime-browser/src/wasm-conformance.test.ts
pnpm exec playwright install --with-deps chromium
node --import tsx tools/test-browser-events.ts
node --import tsx tools/test-browser-peer.ts
node --import tsx tools/test-browser-bridge.ts
```

The build emits `artifacts/wasm/sqlite3.mjs`, `sqlite3.wasm`, `sqlite3-opfs-async-proxy.js`, and `manifest.json`. Serve those four files together. Generated binaries are not committed. The builder uses a detached source copy so generated files cannot modify pnpm's shared cache, and records build arguments to invalidate stale compiler outputs. `manifest.json` records the compiler, native execution manifest, runtime versions, exact deterministic-hook digest, WASM digest and VFS portability patches. Loading verifies the actual WASM bytes before instantiation and checks the SQL versions and security configuration before opening a peer.

The build compiles the same pinned DoltLite 0.11.29, sqlite-vec 0.1.9, and native deterministic hooks. Two storage-specific source patches honor optional SQLite VFS features: sector size uses SQLite's guarded default, and an unsupported file-movement check continues with the ordinary size check. The deterministic VFS wrapper forwards storage calls with the original VFS identity, preserving the OPFS pool's state lookup. The exclusive Worker owns the OPFS namespace. These adaptations do not change SQL semantics. A 2 MiB WASM stack supports the shared bootstrap schema and commit paths.

The six native/WASM conformance tests compare content hashes, logs, deterministic
time/random values, exact typed row keys and storage-class comparisons, the
transaction-id context, sealed writes and policy closure, permissions, SQL
restrictions, budgets, replay/reopen and extension diagnostics. They also execute
mixed SQL/event programs, confirm rollback after a later assertion fails and
retain a SQL read view across a subsequent accepted change. Both engines use the
same v8 native hook profile and v3 program semantics.

The Chromium SQL/OPFS lifecycle gate contains eight checks against the public
client and actual Worker storage: exclusive ownership; signed/encrypted SQL;
mixed SQL/event atomicity and pinned combined reads; final SQL/native state
agreement; graceful identity/operation recovery; exact retry after preparation
termination; a private validator cutoff surviving termination without a
reconstructing feed record; and recovery after candidate SQL commit. It writes
`artifacts/browser-qualification/report.json`.

The six native/WASM tests passed locally and in the complete required
[browser qualification](https://github.com/werg/chronolog-db/actions/runs/43957113710)
for authored head `1b5b8f26`, tested as clean PR merge `3780499f`. That run also
passed all eight SQL/OPFS checks, the SQL-free and enrolled public-peer gates,
both application layouts, and the real workerd thin-administrator scenario.
The [application-log evidence](../../docs/plans/application-log.md) records exact
source/package hashes and raw reports; historical runs retain their own inputs.

The [SQL-free browser gate](../../tools/test-browser-events.ts) serves no engine
assets and no cross-origin isolation headers. It checks the emitted browser
bundle for SQL/WASM implementation bytes, connects an actual OPFS Worker to a
durable native fixed authority through authenticated framed ranges, and checks
bidirectional final events and cursor delivery. It terminates the Worker both
before and after replacing a projection's state/cursor checkpoint, then verifies
that recovery reads the whole prior pair or the whole new pair. A separate abrupt
termination checks a private synchronous cutoff flush. It writes
`artifacts/browser-events/report.json` and `bundle.json`. The native HTTP fixture
has its own integration test for exact range/evidence exchange; it does not
qualify NAT traversal or production network reachability.

The combined [browser and native gate](../../tools/test-browser-bridge.ts) uses the pinned public Tendriller SDK and optional adapter against an independent durable reference HTTP log with its own authenticated prefix authority. A browser enrolls through the public client with fresh private keys and explicit full-history approval, then accepts membership in a collective shared with a native agent. Both claim the same collective-owned SQL task before certification; actual native and WASM execution must agree on exactly one final success and one assertion rejection. A page reload must retain the same keys, signed request, SQL state and transaction identity. Finally, a fresh approved reader obtains historical keys, original signed records and certificates from the first browser peer over the ordinary `FeedLink` interface while the hub is offline. It must reach the same final SQL hash without contacting the log or authority. This gate writes `artifacts/browser-bridge/report.json`; the actual Tendriller Worker routes have their own backend tests.

The [browser qualification workflow](../../.github/workflows/browser-peer.yml) builds the engine and requires the browser gates, so an absent artifact cannot silently skip qualification. For environments unable to launch Chromium, `tools/test-browser-events.ts --build-only` verifies the SQL-free emitted graph and `tools/test-browser-peer.ts --build-only` compiles the SQL/events fixtures; these checks do not substitute for the actual browser runs.

Set `CHRONOLOG_CHROMIUM_EXECUTABLE` to an existing Chromium or Chrome Headless Shell executable when using an externally installed browser. Set `CHRONOLOG_WASM_DIRECTORY` to test a different artifact directory. The ordinary test suite skips the engine comparison when no generated artifact exists; the required CI gate sets `CHRONOLOG_REQUIRE_WASM=1`.

## Host requirements

Both profiles need a secure origin, OPFS, Web Locks, WebCrypto Ed25519/X25519,
and a dedicated Worker. The events profile additionally needs synchronous OPFS
access handles for its private control journal. It does not require WebAssembly,
SharedArrayBuffer, or cross-origin isolation.

For the SQL/events profile, serve the application and engine with cross-origin isolation:

```http
Cross-Origin-Opener-Policy: same-origin
Cross-Origin-Embedder-Policy: require-corp
```

The SQL/events profile also requires WebAssembly and SharedArrayBuffer. Each profile fails explicitly if its prerequisites are unavailable. One exclusive Web Lock covers each peer name for its whole lifetime. A second tab or Worker must connect to that owner or use a different peer name. Worker termination releases ownership; the next owner validates durable state and recovers it before serving RPC.

OPFS stores immutable feed objects before publishing the atomic manifest that references them. Private operation and key records use atomic file replacement. SQL uses SQLite's OPFS synchronous-access-handle pool in a separate private directory. That VFS supports the shared materializer's multiple reader/candidate connections inside one storage owner; normal close pauses the pool and releases all handles without deleting data. The independent SQL control database commits cutoff updates synchronously with FULL durability before signing decisions. The application database uses the shared DoltLite publication/recovery protocol. Private stores and keys never enter feed replication.

The SQL-free profile instead appends checksum-protected private control records
to a synchronous OPFS journal and flushes each append before acknowledging it.
Recovery removes only an incomplete unacknowledged tail; a corrupt complete
frame fails closed. Its bounded event execution anchor atomically retains the
accepted/rejected outcome history and applied final frontier. No SQL file or
engine is needed to recover durable events, operation identity, or cutoffs.

## Worker and page composition

The application supplies its verified group descriptor, execution manifest and routing identity. `configure` runs inside the Worker after opening the durable identity and feed store. It can connect the local `PortableFeedTransport` to a retained-history `FeedLink`, or wrap it in a transport adapter such as the optional Tendriller bridge.

Opening either browser profile loads an existing device identity. Missing keys
fail with `ENROLLMENT_IDENTITY_MISSING` before application bootstrap; malformed
keys also fail. Only deliberate first-device setup passes `createIdentity: true`
(or calls `prepareBrowserIdentity(name, true)` in its explicit enrollment stage).
Preparation persists an empty feed before creating keys and completes their
identity binding before returning a usable identity. Never add that flag in an
automatic recovery catch block. After browser storage is cleared, show that the
device needs recovery or new enrollment, retain any externally saved original
operation references, and require an explicit decision before creating a new
identity. A new identity has no inherited grants or local operation journal.
Use a new peer name when enrolling a replacement device; revoke the lost device
through the administrator. A surviving replica can supply authorized history,
but cannot reconstruct that device's erased private keys or unpublished drafts.
Existing keys always require their retained feed manifest and matching identity
binding, even when explicit creation is requested. Missing `feed/manifest` fails
with `BROWSER_FEED_MANIFEST_MISSING`; losing both manifest and binding still
cannot restart that signer at sequence one. A missing/mismatched binding also
fails. Incomplete final setup requires verified restore or a new device name.
An ambiguous durable write fences the live feed store with
`FEED_STORE_REOPEN_REQUIRED` until reopening reconciles its committed head.
These checks do not prove that an arbitrary backup is current or that
independently copied stores have one active writer.
The [device boundary runbook](../../docs/device-boundary-qualification.md) records
actual Chromium quota/storage-clear scenarios, protocol authorization checks and
the physical-device/deployed-authentication work that remains separate.

```ts
// peer-worker.ts
import { openBrowserPeer, serveBrowserPeer } from '@chronolog/runtime-browser'
import type { BrowserPeerConfiguration, WorkerEndpoint } from '@chronolog/runtime-browser'
import { groupConfiguration } from './group-configuration.js'

const peer = await openBrowserPeer({
  name: 'shared-notes',
  engineUrl: new URL('/engine/', self.location.href),
  configure: async ({ transport }) => {
    // These values are provided by the application's signed group bootstrap.
    const { genesis, executionManifest, groupRoute, relay } = await groupConfiguration()
    const configuration: BrowserPeerConfiguration = {
      materializer: {
        executionManifest,
        rootAdministrator: genesis.manifest.schemaAdminPublicKey,
      },
      governed: { genesis, groupRoute },
      start: async () => { transport.connect(relay); await transport.catchUp() },
    }
    return configuration
  },
})
serveBrowserPeer(self as unknown as WorkerEndpoint, peer)
```

`groupConfiguration` above is application bootstrap code, not an API supplied by Chronolog. It returns the signed genesis descriptor, its matching execution manifest, the public group routing bytes and a `FeedLink`. The local peer can start without a relay and reconnect later. The test [Worker fixture](../../test/browser/peer-worker.ts) shows a complete self-contained signed-group bootstrap, including validator configuration and durable storage of the genesis descriptor.

```ts
// page.ts
import { ChronologClient } from '@chronolog/client'
import { WorkerRpcTransport } from '@chronolog/runtime-browser'
import { groupId } from './group-configuration.js'

const worker = new Worker(new URL('./peer-worker.js', import.meta.url), { type: 'module' })
const transport = new WorkerRpcTransport(worker)
const client = new ChronologClient({ transport, groupId })
```

Use the application's Worker readiness message before the first client call. SQL results, transactions, enrollment and finality use the shared client contract. The Worker bridge pulls stream items only when the page advances its iterator and forwards cancellation and deadlines. Call `transport.close()` before intentional Worker termination to flush and release the peer normally.

Governed peers expose the shared enrollment service automatically. An applicant creates and exports its signed request, an authorized administrator approves that exact request, and the applicant observes connection, capability, encryption-key, history and materialization readiness through the shared status API. The private applicant key bundle remains in OPFS. For a validator, supply the signed group's validator settings in `governed.validator`; durable cutoff storage is already part of the browser runtime.

Local and final SQL remain separate views. A final query reads the materialized prefix established by the group's policy. Browser tab lifetime and relay acknowledgements do not establish finality.

For an event-only Worker, use the narrower entry point and omit the engine:

```ts
import { openBrowserEventPeer, serveBrowserEventPeer } from '@chronolog/runtime-browser/events'

const peer = await openBrowserEventPeer({
  name: 'conversation',
  configure: async ({ transport, executionManifestDigest }) => {
    const { genesis, groupRoute, relay } = await eventGroupConfiguration(executionManifestDigest)
    return {
      governed: { genesis, groupRoute },
      start: async () => { transport.connect(relay); await transport.catchUp() },
    }
  },
})
serveBrowserEventPeer(self, peer)
```

`eventGroupConfiguration` is application bootstrap: it verifies the event profile
binding in the signed descriptor and supplies an authorized retained-history
link. The [event Worker fixture](../../test/browser/event-worker.ts) shows a full
OPFS lifecycle with authenticated native framing. Durable application consumers
save their processed `scannedThrough` cursor together with reducer state; RPC
delivery acknowledgment alone never commits application progress.

## Compact membership bootstrap

A newly enrolled Worker calls `peer.governed.ingestMembership(page)` with the
compact host pages. The owning Worker verifies the signed cumulative control
root, original control cutoffs and covering certificate, then activates grants
and unwraps keys. No application receipt is imported by this operation, so
enrollment remains pending until authenticated peers provide the full original
ledger and bodies. The proof is durable across Worker restart. See
[compact membership proofs](../../docs/membership-control-proofs.md).
