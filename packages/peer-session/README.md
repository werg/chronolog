# `@chronolog/peer-session`

Public application session for Node.js and browser Workers. Owns device identity, durable storage, commands, queries, events, live signals, chunked content, epoch keys, peer networking, control sync, and recovery.

## Entrypoints

| Import | Purpose |
| --- | --- |
| `@chronolog/peer-session` | Definitions, session types, tools (`createApplicationTools`, `createScopedApplicationTools`), `createLiveView`, `forwardSessionEvents`, `createViewStore`, `operationReference`, `SessionError`, `canonicalJson`, control participant, owner lock, and authority helpers |
| `@chronolog/peer-session/native` | `openNativeDevice`, `openNativeApplication`, `NativeBytesStore` |
| `@chronolog/peer-session/worker` | `openBrowserDevice`, `openBrowserApplication`, `serveApplicationWorker`, `probeBrowserCapabilities`, `createApplicationOwner` |
| `@chronolog/peer-session/browser` | Page-side facade: `connectApplicationWorker`, `connectApplicationOwner`, `createLiveView`, `createViewStore`, `operationReference`, `SessionError` (no keys or durable storage) |
| `@chronolog/peer-session/webrtc` | `openWebRtcConnection`, `connectApplicationWebRtc`, Worker RTC bridge |
| `@chronolog/peer-session/webrtc-native` | `createNativePeerConnection`, `connectNativeApplicationWebRtc` |
| `@chronolog/peer-session/websocket` | Dual-socket WebSocket peer connection |
| `@chronolog/peer-session/tendriller` | `createApplicationBackend` adapter for Tendriller browser runtime |
| `@chronolog/peer-session/sql` | `prepareSqlApplication`, `openSqlApplication` (in SQL archives) |
| `@chronolog/peer-session/sql-native` | `createNativeSqlEngine` (native DoltLite) |
| `@chronolog/peer-session/sql-browser` | Browser WASM DoltLite loader |

Browser entries never load Node or Werift modules. Passive protocol imports keep durable storage lazy (`status.database === 'idle'`) until first durable read/write.

## Define an application

```ts
import { defineApplication, defineCommand, defineQuery, emit, program } from '@chronolog/peer-session'

export const notesApp = defineApplication({
  id: 'notes-v1',
  version: '1',
  commands: {
    addNote: defineCommand({
      description: 'Add a note',
      input: { type: 'object', properties: { text: { type: 'string', minLength: 1 } }, required: ['text'], additionalProperties: false },
      prepare: ({ text }) => program(emit('note', { text })),
    }),
  },
  queries: {
    notes: defineQuery({
      description: 'List notes',
      input: { type: 'null' },
      read: view => view.readEvents({ topics: ['note'] }).events,
    }),
  },
})
```

For guarded SQL transactions, include `schema` on the definition, sign it with `prepareSqlApplication`, and open with `openSqlApplication({ ..., createEngine })`.

## Open a device and session

**Native (Node.js):**

```ts
import { openNativeDevice, openNativeApplication } from '@chronolog/peer-session/native'

const device = await openNativeDevice({ path: './device.sqlite', mode: 'openOrCreate' })
const session = await openNativeApplication({ device, definition: notesApp, authority })
```

**Browser Worker + page facade:**

```ts
// worker.ts
import { openBrowserDevice, openBrowserApplication, serveApplicationWorker } from '@chronolog/peer-session/worker'

const device = await openBrowserDevice({ name: 'notes-profile', mode: 'openOrCreate' })
const session = await openBrowserApplication({ device, definition: notesApp, authority })
serveApplicationWorker({ session, port: self })

// page.ts
import { connectApplicationWorker } from '@chronolog/peer-session/browser'

const session = await connectApplicationWorker({ port: worker })
```

Existing devices should open with `mode: 'open'` so missing storage fails closed instead of minting a replacement identity.

## Commands, queries, and change streams

```ts
const before = await session.query('notes', null)
const op = await session.command('addNote', { text: 'Hi' }, {
  operationId: crypto.randomUUID(),
  basedOn: before.revision,
})
const applied = await op.applied()   // accepted | rejected at (generation, sequence)
const shared = await op.shared()     // independent peer retention receipt
```

- Retrying `command()` with the same `operationId` and inputs reuses the saved signed attempt.
- Use `session.operations.get(id)` / `inspect(id)` / `wait(id)` to check uncertain writes.
- Use `session.readView()` for multi-query atomic snapshots; always `await view.release()`.
- Iterate `for await (const change of session.changes({ signal }))` for coalesced update and recovery notifications.
- Use `session.defineProjection(...)` for durable derived local projections that reset cleanly across recovery.

## Control participant and publications

Attach a filtered control host (such as Tendriller) without granting it reader access:

```ts
const control = session.connectControlParticipant({ exchange })
await control.refresh()
await control.publish({ files, entry: 'index.html', runtime })
```

To pause coordinator ordering while an owner reviews a signed control change (such as enrolling a browser), call `await session.pauseOrdering(...)` to retain a durable prefix proof before submitting the transition.

## Owned participation and recovery

`session.participate()` owns peer discovery, direct WebRTC attempts, WebSocket relay fallback, authenticated link handover, and automatic recovery observation:

```ts
const participation = session.participate({
  discovery,
  openDirect: ({ peerId, role, signal }) => openWebRtcConnection({ ... }),
  openRelay: ({ peerId, role, signal }) => openWebSocketConnection({ ... }),
  control,
})
```

- **Direct-first, relay-fallback**: attempts direct WebRTC, falls back to opaque encrypted WebSocket relay when needed, and upgrades back to direct on event-driven triggers without polling.
- **Graceful replacement**: drains in-flight authenticated RPCs up to `drainTimeoutMs` (default 5s) when replacing a peer link.
- **Recovery**: `session.recovery.inspect()`, `takeover(control)`, and `handover(control, { to })` execute explicit signed generation transitions. Abandoned operations throw `AbandonedOperationError` and require deliberate reapplication (`reapplyOf`).
- **Epoch keys**: `session.keys.ensure()`, `missing()`, `request()`, `offer()`, and `install()` manage reader encryption keys peer-to-peer.

## Content, signals, and agent tools

- **Content**: `session.content.stage()`, `read(ref, { start, end })`, `retain()`, and `retention()` transfer encrypted 64 KiB chunks peer-to-peer under current reader grants.
- **Signals**: `session.signals.send(topic, payload, opts)` and `subscribe(opts)` share ephemeral signed updates over the live lane.
- **Agent tools**: `createApplicationTools(session)` exposes declared commands/queries as schema-validated tool descriptors for local or remote assistants.
- **Multi-client ownership**: `createApplicationOwner()` and `acquireApplicationOwnerLock()` allow multiple tabs or local attachments to share one owning session while keeping operation scopes, bounded RPC deadlines (`boundedRequest`), and read-view authority isolated.

## Packaging

```sh
node tools/package-peer-session.mjs
node tools/package-peer-session.mjs --sql-native --output artifacts/peer-session-sql
node tools/package-peer-session.mjs --sql-browser --output artifacts/peer-session-sql-browser
```

See [Qualification](../../docs/release-hardening.md) and [Browser storage](../../docs/browser-storage.md) for verification details.
