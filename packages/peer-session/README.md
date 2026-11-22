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

## Owned view and tool helpers

`createLiveView(session, { query, input })` subscribes before its initial coherent
read. `ready({ signal, timeoutMs })` bounds initial readiness; `refresh()` waits
for the next accepted snapshot. Call `close()` to release subscriptions. Session
closure, stream termination and cancellation also release them and reject pending
reads. Late query replies cannot reopen a closed observer.

`forwardSessionEvents({ session, checkpoint, project, deliver, signal })` releases
each captured view before invoking external delivery. It saves the batch cursor
only after all projections and deliveries succeed. Failures leave the last saved
cursor for at-least-once replay, so delivery must deduplicate by event identity.
Recovery during processing stops the forwarder for explicit review; it never
silently resets an old cursor. Cancellation fences later callbacks and checkpoints;
it cannot undo delivery or a checkpoint write already started by the caller.

`createScopedApplicationTools(session, { queries, commands })` defaults to no
permissions. Journal inspection, retry and wait verify the saved signed command
against the allowed name; reapplication requires permission for both the original
and replacement commands. Write/journal results use `operationReference()`'s
application/history/author/operation/attempt/generation identity. A `generation`
argument checks before and after execution; use `basedOn` for an atomic command
revision guard. An error after a write begins does not imply that it was cancelled:
inspect the same operation ID before retrying.

`createViewStore()` retains per-view drafts and operation intent in caller-owned
storage. It validates retained records against their storage-key scope and refuses
to overwrite corrupt or conflicting evidence. It is local bookkeeping, not an
authorization source or a replacement for the session's signed journal.

## Packaging

```sh
node tools/package-peer-session.mjs
node tools/package-peer-session.mjs --sql-native --output artifacts/peer-session-sql
node tools/package-peer-session.mjs --sql-browser --output artifacts/peer-session-sql-browser
```

See [Qualification](../../docs/release-hardening.md) and [Browser storage](../../docs/browser-storage.md) for verification details.


## Quiesced device handoff and disposable sessions

A device move requires the old participant to stop first. Export rejects known
active device/session use. `exportDeviceCheckpoint(store, { secret, persist })`
requires the `persist({ bytes, metadata })` callback to durably retain the encrypted
handoff before retiring the source. Persist into private staging and fsync it;
publish the staged file/directory only after export succeeds. If publication
fails afterward, retain staging for recovery. A failed persistence callback leaves
the source usable. `retireSource:false` is an explicit backup, not a safe move or
permission to run two copies of the same signing identity.

`restoreDeviceCheckpoint(store, bytes, { secret })` requires enumeration and atomic
`putAllIfEmpty`. It never merges with or overwrites existing identity. Memory,
native SQLite and IndexedDB stores implement this primitive; other stores fail
closed until they supply it. Stage a fresh private target, restore any returned
SQL bytes beside it, reopen and verify its device identity, then publish the target
directory as one unit. Checkpoints are bounded to 4096 records, 1024 outbox entries,
16 MiB raw record/SQL data and 32 MiB encrypted data. The caller owns quiescence of
external/direct store writers and consistency of separately captured SQL bytes.

Disposable devices are explicitly ephemeral and non-resumable. Requested memory
store quotas are enforced, and failed SQL-device construction removes its managed
temporary directory. Closing an ergonomic client fences new submissions; cancelling
submitted work reports known/uncertain outcomes without claiming it was rolled back.

Node WASM SQL requires Node's built-in `node:sqlite` for its small OS-released owner
fence, plus the verified WASM engine; no patched native addon is compiled. The VFS
implements per-connection SQLite locks within that owner. The SQLite cache budget
is per connection, not a total process/WASM RSS guarantee; temporary SQL storage
uses files. Unknown budget options fail closed. The loader and WASM binary must
match the hashes in a trusted build manifest. SQL WASM package consumers are
qualified independently on Linux, macOS and Windows in remote CI.
