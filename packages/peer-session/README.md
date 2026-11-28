# `@chronolog/peer-session`

Unified local-first Chronolog session runtime with unified Merkle-DAG CAS, scoped packages, pure WASM, derivations, cross-log mounts, and zero native C/C++ builds.

## Entrypoints

| Import | Environment | Purpose |
| --- | --- | --- |
| `@chronolog/peer-session` | Universal (passive) | `createLogGenesis`, `createRegistryGenesis`, `createApplicationSession` (lazy-loads runtime), `openApplicationDevice`, `createLiveView`, `forwardSessionEvents`, `createScopedApplicationTools`, `createApplicationOwner`, `exportLogBlueprint`, `validateLogBlueprint`, `dryRunReducerUpgrade` (lazy), `attachCasPinner`, `MemoryBytesStore`, encrypted checkpoints. |
| `@chronolog/peer-session/kernel` | Edge / Workers / Node | `TopicKernel`, `QuickJsSandbox`, `WasmSandbox`, `replayBlindHostControl`, `collectControlReferencedCasHashes`, `dryRunReducerUpgrade`, `evaluateDerivation`, `ContentAddressedStore`, CAS object codecs (`pkg`/`tree`/`blob`/`drv`). Zero `node:*` imports. |
| `@chronolog/peer-session/mirror` | Edge / Workers / Node | WinterCG-native `createCasMirrorHandler`, `createCasMirrorClient`, `createBytesStoreCasMirrorStore`, `createCasAdapterMirrorStore`, `resolveTrustedBuildOutput` for `/cas/:hash` (`?subgraph=1`), `/derivations/:drvHash`, `/audits/:pkgHash`, and `/trees/:treeHash/*path`. Zero `node:*`, QuickJS, or SQLite imports. |
| `@chronolog/peer-session/native` | Node.js >= 22.15 | `openNativeDevice`, `openDisposableNativeDevice`, `NativeBytesStore` (built-in `node:sqlite`, zero `node-gyp`). |
| `@chronolog/peer-session/browser` | Browser main thread | Passive `WorkerApplicationSession` facade (`connectApplicationOwner`), `createLiveView`, `createViewStore`, `createScopedApplicationTools`. Zero storage/QuickJS/SQLite imports. |
| `@chronolog/peer-session/worker` | Browser Worker | `openBrowserDevice`, `createApplicationSession`, `createApplicationOwner`, `acquireApplicationOwnerLock`. |
| `@chronolog/peer-session/webrtc` | Universal | WebRTC peer connection adapter (`openWebRtcConnection`, `serveWorkerWebRtcConnections`). |
| `@chronolog/peer-session/webrtc-native` | Node.js | Pure-JS native WebRTC via `werift` (`createNativePeerConnection`). |
| `@chronolog/peer-session/websocket` | Universal | WebSocket framed peer channel adapter. |
| `@chronolog/peer-session/sqlite-cas.wasm` | Static WASM asset | Pre-built SQLite + FTS5 + `sqlite-vec` CAS WASM module for Cloudflare Workers and bundlers. |

## Core Session API

- **Authoring & Reading:** `session.submit({ updates })`, `session.command(...)`, `session.topic(name)`, `session.query(name, input)`, `session.describe()`, `session.readView({ view })`, `session.readEvents(options)`.
- **Packages, Derivations & Mounts:** `session.installPackage(...)`, `session.mountLog(name, source)`, `session.evaluateDerivation(drvRef, options)` (with local memo + trusted `$builders` mirror attestation cache), `casMirrors`.
- **Membership & Keys:** `session.admitMember(...)`, `session.rotateEpoch(...)`, `session.removeMember(...)`.
- **Releases, Reducers & Finality:** `session.publishRelease(...)` (emits unified `chronolog-tree/v1` `treeRoot` + public CAS blobs), `session.updateReducers(...)`, `session.scheduleFinality(...)`, `session.finality.*`.
- **Replication & GC:** `session.connectPeer(...)` (`sync-v3` + subgraph `cas-want`), `session.exportFacts(...)`, `session.exportCasNodes(..., { subgraph })`, `session.mergeFacts(...)`, `session.collectGarbage()`.
- **Ephemeral Signals & Unified Blobs:** `session.signals` (`$signal_policy`-enforced live lane), `session.content` (unified `chronolog-blob/v1` / `chronolog-enc-blob/v1` over `session.cas`).
