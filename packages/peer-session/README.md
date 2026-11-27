# `@chronolog/peer-session`

Unified local-first Chronolog v2 session runtime with zero native C/C++ builds.

## Entrypoints

| Import | Environment | Purpose |
| --- | --- | --- |
| `@chronolog/peer-session` | Universal (passive) | `createLogGenesis`, `createApplicationSession` (lazy-loads runtime), `openApplicationDevice`, `createLiveView`, `forwardSessionEvents`, `createScopedApplicationTools`, `createApplicationOwner`, `createApplicationBackend`, encrypted checkpoints. |
| `@chronolog/peer-session/native` | Node.js >= 22.15 | `openNativeDevice`, `openDisposableNativeDevice`, `NativeBytesStore` (built-in `node:sqlite`, zero `node-gyp`). |
| `@chronolog/peer-session/browser` | Browser main thread | Passive `WorkerApplicationSession` facade (`connectApplicationOwner`), `createLiveView`, `createViewStore`, `createScopedApplicationTools`. Zero storage/QuickJS/SQLite imports. |
| `@chronolog/peer-session/worker` | Browser Worker | `openBrowserDevice`, `createApplicationSession`, `createApplicationOwner`, `acquireApplicationOwnerLock`. |
| `@chronolog/peer-session/webrtc` | Universal | WebRTC peer connection adapter (`openWebRtcConnection`, `serveWorkerWebRtcConnections`). |
| `@chronolog/peer-session/webrtc-native` | Node.js | Pure-JS native WebRTC via `werift` (`createNativePeerConnection`). |
| `@chronolog/peer-session/websocket` | Universal | WebSocket framed peer channel adapter. |
| `@chronolog/peer-session/sqlite-cas.wasm` | Static WASM asset | Pre-built SQLite + FTS5 + `sqlite-vec` CAS WASM module for Cloudflare Workers and bundlers. |

## Core Session API

- **Authoring:** `session.submit({ updates })`, `session.command(name, input, options)`.
- **Reading:** `session.topic(name)`, `session.query(name, input)`, `session.describe()`, `session.readView({ view })`, `session.readEvents(options)`.
- **Membership & Keys:** `session.admitMember(...)` (atomic `$permissions` + historical HPKE `$keys` lockboxes), `session.rotateEpoch(...)`, `session.removeMember(...)`.
- **Releases, Reducers & Finality:** `session.publishRelease(...)`, `session.updateReducers(...)`, `session.scheduleFinality(...)`, `session.finality.{status, createCheckpoint, submitCheckpoints, bootstrapFromCheckpoint}`.
- **Replication & GC:** `session.connectPeer(...)`, `session.exportFacts(...)`, `session.mergeFacts(...)`, `session.collectGarbage()`.
- **Ephemeral Signals & Blobs:** `session.signals` (`$signal_policy`-enforced live lane), `session.content` (chunked encrypted blobs).
