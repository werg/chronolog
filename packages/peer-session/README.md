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

## Run a device inside celld

The `@chronolog/peer-session/celld` entry uses a celld Durable Object's
SQLite storage for the same device identity and application session.

```ts
import { openCelldApplication, openCelldDevice } from '@chronolog/peer-session/celld'

const device = await openCelldDevice({ storage: ctx.storage })
const session = await openCelldApplication({ device, definition, authority })
```

Pass `create: true` during explicit device setup. Later activations reopen
the retained signer and history. Provide `openDataStorage` to open a
separate SQLite facet on demand. Closing the device releases its handles
within the Durable Object. Pass `frameCelldPeerStream(stream)` as the
`connection` to `session.connectPeer()` for streams opened or accepted
by the same object. The session authenticates the peer's application
identity. The Iroh node ID identifies the transport endpoint.

For a host-managed device, declare the Ed25519 private key as a class
secret. Use the admitted public key and the secret's lowercase PKCS#8 hex
value on every activation.

```ts
import { importCelldSigningIdentity, openCelldDevice } from '@chronolog/peer-session/celld'

const managedSigner = await importCelldSigningIdentity(admittedPublicKey, env.CHRONOLOG_SIGNER_PKCS8)
const device = await openCelldDevice({ storage: ctx.storage, managedSigner })
```

Pass `create: true` on the initial managed enrollment. The device metadata
keeps only the public identity and its storage binding. A missing or
different key prevents resume. The same imported identity can sign
generation selections through `openCelldApplicationControl` where it
matches that application's registered control key.

### Invite a device

After the control object selects a generation with the member's reader
grant, an admitted administrator can sign a celld invitation with
`signCelldApplicationInvitation({ authority, memberPublicKey, endpoint, inviter })`.
Use the administrator device's Ed25519 identity and its actual Iroh
endpoint. The signed invitation carries the selected authority and
endpoint. Epoch keys remain on the authenticated peer link.

On the invited device, call
`acceptCelldApplicationInvitation(device, invitation)`. It checks the exact
member key, signature and signed control history, and retains the authority
before opening the application. Pass the returned `authority` to
`openCelldApplication` and use the returned `peer` and `endpoint` with
`createCelldPeerTransport`. The application session authenticates that peer
and synchronizes the selected history over the connection.

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

- **Content**: `session.content.stage()`, `read(ref, { offset, length })`, `retain()`, and `retention()` transfer encrypted 64 KiB chunks peer-to-peer under current reader grants.
- **Signals**: `session.signals.send(topic, payload, opts)` and `subscribe(opts)` share ephemeral signed updates over the live lane. With `mode: 'latest'`, an active subscription coalesces newly received updates; it does not return a current-value snapshot or replay earlier messages.
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


Use `--sql-celld` to include the signed SQL and workspace adapters for celld. The release workflow attests this archive for host builds.

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
directory as one unit. The byte-array compatibility APIs materialize the checkpoint;
optional `limits: { maxBytes, maxEntries, maxValueBytes }` set caller budgets rather
than imposing a smaller fixed quota than the source store. Outboxes remain bounded
to 1024 records. The caller owns quiescence of external/direct store writers and
consistency of separately captured SQL bytes.

For large stores, use `exportDeviceCheckpointStream(store, { secret, sink })`.
The sink receives bounded binary AES-GCM frames through `write(bytes)` and must
resolve `commit(metadata)` only after the complete checkpoint is durable. Source
retirement follows commit. Supply `retireSource: false` for a backup. Optional
`sqlDatabase: { bytes, chunks }` streams quiesced SQL bytes without copying the
whole database into the checkpoint encoder. Frame counters and an authenticated
footer reject reordered, truncated, or trailing input.

`restoreDeviceCheckpointStream(target, encryptedChunks, { secret, limits, sqlSink })`
uses `putStreamIfEmpty` to stage entries and atomically publish them only after the
whole input authenticates. The target must be fresh. Memory, native SQLite and
IndexedDB implement this primitive; other stores fail closed. A SQL sink stages
its bytes separately and commits only after authentication; publish its SQL output
and the restored target together as one private device directory. Without a SQL
sink, SQL bytes are returned in memory. Streaming has no fixed aggregate quota;
memory use follows one store value and bounded transport pages/frames. Individual
values and the destination store remain subject to their configured quotas.

Native records use stable prebuilt `better-sqlite3` bindings in a dedicated worker.
Await `NativeBytesStore.open(path, options)` for acquisition and `await store.close()`
for durable release before reopening or deleting the file. `checkpointWal()` also
returns a promise; `usageBytes()` reports the last completed worker operation.
Existing `node:sqlite`-created stores reopen without conversion. No native C/C++
compilation is required on platforms supplied by the binding's prebuilt packages.

Peer hello and state exchanges use authority summaries and signed missing suffixes.
Use `connectPeer({ ..., authorityExchange: 'bundle' })` when connecting to an older
endpoint that only understands complete bundles. Registry state migrates existing
bundles to an append log on the first successful selection. Signed records are
written before the small head; failed head acknowledgments are resolved by retrying
the exact transition ID.

Replica startup reads and hashes original journal/record bytes in bounded batches.
Small HMAC attestations, keyed from the local signing identity through HKDF, allow
unchanged originals to reuse prior origin/receipt verification; they contain no
plaintext command bodies. Invalid or stale attestations trigger full verification.
Only a clean close writes optional attestations. They are acceleration data, never
an alternative source of history. `createPeerReplica({ ..., verificationCache: false })`
forces a full cryptographic audit. Retained encrypted bodies and decoded cores are
shared by the replica's internal indexes.

Disposable devices are explicitly ephemeral and non-resumable. Requested memory
store quotas are enforced, and failed SQL-device construction removes its managed
temporary directory. Closing an ergonomic client fences new submissions; cancelling
submitted work reports known/uncertain outcomes without claiming it was rolled back.

Node WASM SQL uses prebuilt `fs-native-extensions` OS locks on the database inode,
plus the verified WASM engine. It creates no SQLite owner sidecar and needs no
experimental Node SQLite API. Stop all older runtimes before removing obsolete
`<db>.chronolog-owner.sqlite` files (and their WAL/SHM companions). The new VFS
refuses a database with an old marker because older processes use a different
ownership fence. The VFS
implements per-connection SQLite locks within that owner. The SQLite cache budget
is per connection, not a total process/WASM RSS guarantee; temporary SQL storage
uses files. Unknown budget options fail closed. The loader and WASM binary must
match the hashes in a trusted build manifest. SQL WASM package consumers are
qualified independently on Linux, macOS and Windows in remote CI.
