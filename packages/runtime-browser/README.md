# Browser peer runtime

This package runs a complete Chronolog peer in one dedicated browser Worker. The Worker owns signing and reader keys, exact signed feed records, immutable ordering evidence, durable operation state, the control index, validator cutoffs, and a real DoltLite database in OPFS. The page uses the ordinary `ChronologClient` through `WorkerRpcTransport`.

The same protocol, membership, admission, history policy, materializer, SQL restrictions, enrollment service, and RPC contract run in native and browser peers. `openBrowserPeer` supplies the browser storage and engine adapters. A group chooses its peer or coordinated history policy in its signed genesis descriptor; selecting a transport does not change that policy.

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
node --import tsx tools/test-browser-peer.ts
```

The build emits `artifacts/wasm/sqlite3.mjs`, `sqlite3.wasm`, `sqlite3-opfs-async-proxy.js`, and `manifest.json`. Serve those four files together. Generated binaries are not committed. `manifest.json` records the compiler, native execution manifest, runtime versions, exact deterministic-hook digest, WASM digest and VFS portability patch. Loading verifies the actual WASM bytes before instantiation and checks the SQL versions and security configuration before opening a peer.

The build compiles the same pinned DoltLite 0.11.29, sqlite-vec 0.1.9, and native deterministic hooks. Two storage-specific source patches honor optional SQLite VFS features: sector size uses SQLite's guarded default, and an unsupported file-movement check continues with the ordinary size check. The exclusive Worker owns the OPFS namespace. These patches do not change SQL semantics. A 2 MiB WASM stack supports the shared bootstrap schema and commit paths.

Native/WASM conformance compares content hashes, logs, deterministic time and random values, integer/real/blob handling, assertions, permissions, SQL restrictions, replay, reopening, budgets, and the supported extension engine diagnostics. The separate Chromium gate executes the public client against actual Worker SQL and OPFS, rejects a competing owner, queries the real final view, reopens durable identity and operation state, and terminates the Worker at preparation and SQL publication boundaries before recovering. It writes `artifacts/browser-qualification/report.json`. The [browser qualification workflow](../../.github/workflows/browser-peer.yml) builds the engine and requires both gates, so an absent artifact cannot silently skip qualification.

Set `CHRONOLOG_CHROMIUM_EXECUTABLE` to an existing Chromium or Chrome Headless Shell executable when using an externally installed browser. Set `CHRONOLOG_WASM_DIRECTORY` to test a different artifact directory. The ordinary test suite skips the engine comparison when no generated artifact exists; the required CI gate sets `CHRONOLOG_REQUIRE_WASM=1`.

## Host requirements

Serve the application and engine from a secure origin, with cross-origin isolation:

```http
Cross-Origin-Opener-Policy: same-origin
Cross-Origin-Embedder-Policy: require-corp
```

The runtime requires OPFS, Web Locks, WebCrypto Ed25519/X25519, Workers, WebAssembly and SharedArrayBuffer. It fails explicitly if these prerequisites are unavailable. One exclusive Web Lock covers each peer name for its whole lifetime. A second tab or Worker must connect to that owner or use a different peer name. Worker termination releases ownership; the next owner validates durable state and recovers it before serving RPC.

OPFS stores immutable feed objects before publishing the atomic manifest that references them. Private operation and key records use atomic file replacement. SQL uses SQLite's OPFS synchronous-access-handle pool in a separate private directory. That VFS supports the shared materializer's multiple reader/candidate connections inside one storage owner; normal close pauses the pool and releases all handles without deleting data. The independent SQL control database commits cutoff updates synchronously with FULL durability before signing decisions. The application database uses the shared DoltLite publication/recovery protocol. Private stores and keys never enter feed replication.

## Worker and page composition

The application supplies its verified group descriptor, execution manifest and routing identity. `configure` runs inside the Worker after opening the durable identity and feed store. It can connect the local `PortableFeedTransport` to a retained-history `FeedLink`, or wrap it in a transport adapter such as the optional Tendriller bridge.

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
        rootAdministrator: genesis.manifest.rootAdminPublicKey,
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
