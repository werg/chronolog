# Peer application sessions

`@chronolog/peer-session` owns the application runtime. All participants use the
same signed records, operation journal, replication, materialization and query
contracts. `peer-generation-v1` identifies the signed record format; it is not
an application mode or a selector for a second implementation.
One eligible peer sequences commands. Ordinary commands, queries, history and
live signals need no hosted request while that generation is healthy. A signed
control service selects a successor during takeover. Recovery can abandon a
recent suffix, which remains inspectable and requires explicit reapplication.

An applied result is accepted or rejected at one generation and sequence. It is
stable in that history, but is not irreversible finality. This package exposes
no `final()` wait and no automatic external-effect dispatcher.

## Native events application

Create or enroll a device explicitly before opening a session. Resuming a device
never replaces missing keys. The native store holds an exclusive SQLite writer
lock; the browser entry holds an exclusive Web Lock and uses OPFS in the owning
Worker. A second owner receives a busy error.

```ts
import { defineApplication, defineCommand, defineQuery, emit, program,
  type ApplicationReadView } from '@chronolog/peer-session'
import { openNativeDevice, openNativeApplication } from '@chronolog/peer-session/native'

const definition = defineApplication({
  id: 'conversation', version: '1',
  commands: {
    say: defineCommand({
      description: 'Post a message',
      input: { type: 'object', properties: { text: { type: 'string', minLength: 1, maxLength: 2000 } }, required: ['text'] },
      prepare: ({ text }) => program(emit('message', { text })),
    }),
  },
  queries: {
    messages: defineQuery({ description: 'Read messages at one revision', input: { type: 'null' },
      read: (view: ApplicationReadView) => view.readEvents({ topics: ['message'] }),
    }),
  },
})
const device = await openNativeDevice({ path: './device.sqlite' })
const session = await openNativeApplication({ device, definition, authority })
try {
  const before = await session.query('messages', null)
  const operation = await session.command('say', { text: 'Hello' }, {
    operationId: crypto.randomUUID(), basedOn: before.revision,
  })
  const result = await operation.applied()
  console.log(result.generation, result.sequence, result.outcome)
} finally { await session.close() }
```

`authority` is the verified signed descriptor/control/generation bundle obtained
from the configured control service. Enrolled decryption keys persist in the
owned device store; a new reader acquires missing keys from an authorized peer.
`applicationDefinitionDigest(definition)` binds the published
schemas and semantic version. Obtain the event execution manifest with
`eventExecutionManifest()`. Materializers consume verified order through one
execution pipeline; transport roles do not change execution semantics.

Only first device setup passes `{ create: true }`. Ordinary reopening omits it.
The session owns one signed attempt journal in the device store. A disconnected
command remains `saved`; connecting resumes its exact original attempt.
Cancelling `applied({ signal })` cancels that waiter only.

## SQL as an explicit engine capability

SQL uses the same application session, signed schema, commands, views and
replication. The optional `/sql` entry owns schema verification and opening for
both native and browser execution. Its `SqlEngine` supplies exactly an execution
manifest and a database-opening function; it does not create another application
runtime.

```ts
import { prepareSqlApplication, openSqlApplication } from '@chronolog/peer-session/sql'
import { createNativeSqlEngine } from '@chronolog/peer-session/sql-native'

const engine = createNativeSqlEngine()
// First publication signs the literal schema and its application/engine binding.
const prepared = await prepareSqlApplication({
  engine, applicationId, definition, schemaAdministrator: device.identity,
})
// The control participant signs an authority descriptor containing prepared.binding.
const session = await openSqlApplication({
  engine, device, definition, authority, schema: prepared.schema,
  databasePath: './application.sqlite',
})
```

Normal reopening reuses the published signed schema and existing device. It does
not sign a new schema. The common opening function claims device ownership before
constructing a materializer, verifies the schema authority and definition, and
requires the engine manifest to match the descriptor before opening a database.
It captures engine/schema inputs before asynchronous work. Closing the session
releases its SQL views and database handles through the same owned lifecycle as
event execution.

In an owning browser Worker, construct that same capability from verified WASM
and an already owned SQLite VFS:

```ts
import { createBrowserSqlEngine, loadBrowserEngine } from '@chronolog/peer-session/sql-browser'

const loaded = await loadBrowserEngine(engineAssetBaseUrl)
const engine = createBrowserSqlEngine({ ...loaded, vfs: ownedSqlVfsName })
const session = await openSqlApplication({
  engine, device, definition, authority, schema,
  databasePath: '/application.sqlite',
})
```

The Worker owns the initialized VFS and its storage handles. It releases any
OPFS SQL pool only after application database handles have closed, within the
same storage-owner lifetime. The engine adapter does not establish a second
ownership service. Native and browser factories produce the same SQL execution
format and common manifest encoding from the qualified build identity; explicit
execution limits are part of that manifest. There is no application-profile
selector or platform-specific schema path.

Build WASM assets with `tools/build-wasm-engine.mjs` and host its exact
`sqlite3.mjs`, `sqlite3.wasm`, `sqlite3-opfs-async-proxy.js` and `manifest.json`
together. The loader verifies the WASM digest and supported build identity before
instantiation. These engine assets are a separately built artifact, not an
implicit download from a package service. The native/WASM conformance suite
compares replay, state, permissions and SQL security against the same reducer.

## The host as a control participant

```ts
const control = session.connectControlParticipant({
  exchange: (request, { signal }) => client.peers.exchange(request, { signal }),
})
const definition = await control.definition()
const notice = await session.recovery.takeover(control, { transitionId: crypto.randomUUID() })
```

The attachment shares the session's identity and lifetime. It performs no request
until an explicit lifecycle action, and its closed role policy excludes database
bodies, content chunks and ordinary live signals. Peer and hosted transports use
the same scoped participant request and response contract. A transport supplies
delivery; the common signed verifier supplies authority.

`control.preparePublication({ operationId, entry, files })` saves the exact signed
code or page manifest. `control.publish(manifest, assets)` submits it with bounded,
hash-verified assets, and `control.publication()` verifies the selected chain.
Retries preserve the original signed intent and receipt. The selected publication
head persists outside recoverable application history and cannot move backward.

## Enrollment and epoch keys

The device owns one Ed25519 identity and one durable application keyring. An
initial creator passes `epochKeys` to the open function as explicit local
bootstrap; normal reopening loads those keys from the owned store. A newly
granted reader can open without keys and reports `status.phase ===
'awaiting-keys'` until it connects to another reader with the needed keys.

Maintained peer transports acquire missing keys before replay. Each request
signs a fresh ephemeral HPKE receiver together with the application, history,
selected generation, control digest and requested epochs. The donor checks the
current reader grants and signed scope, then wraps the authenticated epoch keys
for that one request. The recipient verifies the donor, request binding and key
commitments before one durable install. A storage acknowledgment lost after
installation is recovered by reopening the same device. The ephemeral receiver
does not become a second persistent device identity.

Any current reader holding a committed key can supply it to another current
reader. Membership grants determine who can receive data; key delivery does not
create a new grant. The host selects signed controls and generations, while
readers exchange decryption keys directly. Revocation and generation changes
expire an in-flight request. Removed readers cannot obtain new epoch keys.

For rotation, adopt the new signed control and generation, then the device that
created the new key calls `session.keys.install(new Map([[epoch, key]]))`.
Other readers acquire the rotated key through their peer connections. Selected
history determines the keys required for replay; content can acquire an older
committed key when a retained attachment needs it. Old keys remain local for
reading retained history and content. Advanced transports can use
`session.keys.request()`, `offer()` and `attachSource()` directly; ordinary
applications use the maintained connection helpers.

## Recovery and inspection

`operations.get(id)` returns saved, applied, abandoned or needsReapply.
`operations.inspect(id, { author })` includes the retained original signed
attempt, preserving real signer provenance. `operation.retry()` reuses those
bytes. `onRecovery()` and `changes()` report coherent generation transitions.
A stale event cursor throws `RecoveredViewError`; reread the new view explicitly.
Recovery notices keep `unknownLoss: true` even when they list known abandoned
work: the selected prefix does not certify the former coordinator's last head.

After inspecting abandoned work, call
`reapply(oldId, name, currentArguments, { operationId: newId, basedOn })`. This
prepares a new signed attempt linked by `reapplyOf`; it never admits the old
attempt silently. Use `originalAuthor` when deliberately reapplying retained
work from another signer. Current permissions and domain guards still apply.

`operation.shared()` observes independently retained complete coverage. It is
separate from `applied()` and does not block ordinary commands. A retained copy
is not a claim that its peer is currently reachable.
Coverage retains one strongest claim per current reader identity, so changing
storage IDs cannot count one signer as several independent peers. Recovery
clears those claims; the new generation needs fresh retention acknowledgments.

## Authenticated peer connections

`session.connectPeer({ connection, peerIdentity?, signal? })` owns an authenticated
connection to another current reader. `connection` supplies reliable framed byte
lanes (`send`, `frames`, `signal`, `close`) and an optional separate lossy `live`
lane. The existing `openWebRtcConnection()` and `frameRtcPeerChannels()` results
implement this structural interface directly, in a native process or an owning
browser Worker. A discovery result identifies a possible route; the session
independently verifies a fresh signed challenge bound to both identities, the
application descriptor, and the signed record format before attaching that route.
An optional `peerIdentity` pins the discovered identity. A control-only host
identity cannot attach without an explicit reader grant.
The hello can carry a newer signed authority bundle, so an existing reader can
verify a newly enrolled peer's grant before checking its proof of possession.

The returned link exposes `peerId`, `signal`, `completion`, `synchronize()` and
`close()`. History requests select one advertised head and check each original
signed command before retaining its ciphertext and replaying it. Retention proofs
refer to an exact locally held prefix. Both directions exchange available history,
including when a fresh device is still recovering an inherited generation.
Explicit synchronization observes a fresh head after any older background pull.
Local history/control changes trigger coalesced peer hints; there is no idle host
polling or application-data HTTP fallback. Pending commands use the session's
existing immutable attempt journal, and retry after reconnection preserves those
original bytes.

Reliable messages are fragmented into at most 48 KiB payloads. Each connection
bounds messages to 32 MiB, queued reliable work to eight messages and 32 MiB,
in-flight requests to four in each direction, and history pages to 32 commands
and 4 MiB. The replica's configured quotas bound retained history; transfer does
not allocate a second whole-history buffer. A session owns at most eight peers and
eight opening handshakes. Defaults are 10 seconds for authentication, 30 seconds
for a queued write or partial message, and 120 seconds per request; callers can
set the three corresponding timeout options up to 120 seconds. Closing fences
pending replies and detaches routes synchronously, then retires transport work.
Already committed commands remain eligible for exact retry after a lost reply.

Signed live signals use only the optional lossy lane and its independent bounded
queue. Congestion drops live traffic before dispatch; it never enters the durable
history queue. Live signal authors and connected peers must remain current
readers. Command submission and ordering additionally recheck current writer
permissions. Reader removal retires the peer connection.

The initial creator provisions its epoch key explicitly. Maintained connections
acquire a granted reader's missing keys through the authenticated keyring port;
each share is HPKE-wrapped for that device's fresh signed request. The request's
recipient and the share's issuer must match their authenticated peer connection.
Keys are never sent in plaintext or through an automatic hosted fallback. Use a
confidential transport such as WebRTC when live signal contents require privacy.

`connectApplications(a, b)` is a built-in in-process transport for embedded peers
and independent-store qualification. It executes this same authenticated framed
protocol over bounded memory byte lanes, including live signals. It is not a
measurement of Internet WebRTC routing. No recipe needs its own application retry
queue.

`session.recovery.takeover(host, { transitionId })` validates this device's
complete recovery point, saves one signed transition request, selects it through
the host, and adopts the verified result. Retry the same transition ID after a
lost hosted reply, including after device reopen. A planned
`session.recovery.handover(host, { coordinator, transitionId })` additionally
requires the successor's signed retention of the exact current prefix. These
methods never reinterpret an excluded branch as an eligible recovery base.

`ApplicationControlHost` recognizes the typed error code
`peer_generation_conflict`; error messages are diagnostic. Direct adapters can
throw the exported `ApplicationControlConflictError`, and HTTP adapters preserve
or map that code. After verifying a competing successor, the session marks its
original signed request superseded and adopts the current authority. That
transition ID is never resubmitted.

The recovery journal retains up to 64 transition attempts, including completed
and superseded attempts. Once full, it refuses new signing and hosted selection
requests. There is no automatic pruning or reset: the application must choose
an explicit device/application lifecycle. Pending exact requests are never
discarded to create room for a different transition.

## Peer connections and Worker ownership

`session.connectPeer({ connection, peerIdentity })` owns the protocol described
above. `connection` implements the shared `FramedPeerConnection` interface from
`@chronolog/records`. Each side calls its own session; the returned
`ApplicationPeerLink` includes its authenticated lifetime and traffic counters.

`link.synchronize()` finishes one captured prefix. Later change hints
coalesce into a separate pass, so a continuously writing coordinator cannot
extend an earlier wait indefinitely. Ranges contain at most 32 commands and
4 MiB, transported in bounded fragments; verified pages are retained before
requesting the next page. The current replica envelope permits at most 4,096
retained records and 64 MiB of history; lower configured quotas still apply.
There is no smaller whole-history network buffer limit. For a published source,
the selected view is published only after the captured root is available, and
the retention acknowledgment names that captured prefix. If recovery excludes
the captured generation during transfer, the pass fails explicitly; reconnect
or synchronize against the newly selected history. The lower-level replica
accepts command arrays or an async iterable of bounded command pages through
`synchronize(authority, commands, { at: capturedRevision })`.
A source without a complete published target can still transfer its contiguous
retained evidence. A recovering receiver stays unavailable until the selected
inherited prefix is complete.

A congested live lane refuses the current send without queuing it or closing
the reliable connection. Ending that lane retires its live route. A dispatched
write that ignores cancellation retires the physical connection, preventing
late work from surviving into its replacement. Connecting the same authenticated
peer again closes its previous connection. Signal sends always use routes
available when that attempt began; reconnecting never replays missed signals.

The `/webrtc` entry provides `connectApplicationWebRtc(session, options)` for a
runtime with a usable RTC factory. The optional `/webrtc-native` entry supplies
`connectNativeApplicationWebRtc(session, options)` with the exact supported
Werift implementation. Returned connections expose reliable framed byte counts (including authentication and fragmentation),
request counts, and `rtc.getRoute()` observations. An unknown observed route
stays unknown.

In a browser, install `installApplicationWorkerTransport(session, self)` beside
the Worker-owned session. The page calls
`connectWorkerApplicationWebRtc(worker, { role, signaling, peerIdentity })`.
The helper transfers both negotiated channels synchronously, owns the dedicated
control port, and waits for authentication and initial replay. The page retains
the peer connection for ICE lifecycle and route diagnostics. This API requires a
browser that supports transferring RTC data channels; unsupported browsers fail
explicitly. Actual browser qualification is separate from native stream tests.

The WebRTC CI workflow runs `tools/test-peer-session-webrtc.ts` with actual
Chromium, a DedicatedWorker holding OPFS, and a native SQLite peer. Its separate
source-bound report checks authenticated reconnection with the original saved
attempt, peer commands, signed live signals and encrypted content after the page
and signaling HTTP server stops, then an offline session reopen. The artifact
contains the emitted page and Worker JavaScript as well as their hashes. A local
`--build-only` run checks the browser graph without claiming browser execution.
This fixture provisions epoch keys explicitly and uses loopback ICE; it does not
qualify hosted enrollment, automatic key delivery, public NAT traversal or TURN.

A session with a selected recovery prefix that has not arrived reports
`status.phase === 'recovering'`. Queries fail with `PEER_RECOVERING` until a
complete verified prefix is materialized. Change subscriptions wait for that
first coherent view. Sessions permit at most eight simultaneously held read
views; release them promptly. Closing the session releases all remaining views
and connections before closing its durable store.

## Page facade

The Worker opens the device and owns the application. For RTC connections,
install both owners before announcing that the Worker is ready:

```ts
import { serveApplicationWorker } from '@chronolog/peer-session/browser'
import { installApplicationWorkerTransport } from '@chronolog/peer-session/webrtc'

installApplicationWorkerTransport(session, self)
serveApplicationWorker(session, self, { host })
```

The page facade and RTC transport use separate message namespaces. Serving the
facade alone does not receive transferred RTC channels; the transport owner is
optional when the application does not use RTC.

The page connects through a dedicated message port:

```ts
import { connectApplicationWorker } from '@chronolog/peer-session/browser'

const session = await connectApplicationWorker<typeof definition>(worker)
const before = await session.query('messages', null)
const operation = await session.command('say', { text: 'Hello' }, {
  operationId: crypto.randomUUID(), basedOn: before.revision,
})
const result = await operation.applied()
```

The returned `WorkerApplicationSession` provides the same declared commands,
queries, operation inspection, retry, explicit reapplication, changes, live
signals and content handles. `status` and `revision` are synchronous snapshots;
`describe()` returns the application contract. `onStatus()` and `onRecovery()`
observe updates, while `inspectRecovery()` loads retained recovery notices.
`readView()` holds one coherent SQL/event view until `release()` resolves.
Only the Worker holds signing keys and the durable command journal. Cancelling
a page waiter ends that observation and leaves the saved command inspectable.

The optional `host` stays in the Worker for `recovery.takeover()` and
`recovery.handover()`; ordinary commands do not call it. The bridge serves one
page facade, bounds pending requests and pulled streams, and releases held views
on close. `session.close()` resolves after the Worker has released the owned
device store, so the page can safely reopen it immediately afterward.

The `/tendriller` entry exports `createApplicationBackend()` for
binding either an owned native session or this page facade to Tendriller's
application interface. It forwards declared commands and coherent views to the
same session instead of introducing another identity or queue.
SQL availability comes from `session.capabilities.sql`, including across the
Worker bridge. The adapter requires no separate SQL flag. A definition with a
schema must use an SQL materializer; opening it with the default event runtime
fails before that runtime is initialized.

## Content and local agent tools

`session.content.stage({ bytes, mediaType })` returns an upload handle with
bounded `write(index, bytes)`, `progress()` and `commit()` methods. `resume(id)`
reopens an interrupted upload. Only a complete upload produces a content
reference. References and encrypted 64 KiB chunks are separate from command
history. Readers fetch missing chunks from authenticated peers, verify them,
and retain verified chunks for bounded resumption.

`content.read(reference, { offset, length, signal })` yields plaintext chunks.
`content.retain(reference)` fetches the complete object and attempts to announce
its signed durable-copy observation to available sources. A lost notification
does not invalidate the retained copy. `content.retention(reference)` reports
those observations. Missing content returns `CONTENT_UNAVAILABLE`
without invalidating the application history that refers to it. Current read
permissions are rechecked at every fetch; a reference is never a credential.

`createApplicationTools(session, { host })` derives local query/command tool
schemas from the same application definition. It exposes inspection, exact
retry, wait, recovery inspection and explicit reapplication. A host port enables
the takeover tool. `serveApplicationToolLines(session, { input, write, host })`
accepts bounded JSON lines such as
`{"id":1,"tool":"command","input":{"name":"say","input":{"text":"Hello"},"operationId":"message-1"}}`.
Use `tool: "list"` for schemas and `tool: "wait"` with the operation ID for its
current applied result. The transport creates no second identity, outbox, or
hosted command proxy.

The portable entry and the browser entry are SQL-free. SQL applications supply
a qualified materializer through the same execution contract; the pinned schema
is initialized before application history. Irreversible effects require a
separately declared protected boundary.

## Build a packed preview

Run `node tools/package-peer-session.mjs`. The tarball includes shared ESM chunks,
self-contained TypeScript declarations, and commit/tree/file-hash provenance.
`--allow-dirty` produces an explicitly marked development artifact. Native and
browser entries share session classes and ownership state through those chunks.
Use `--native-rtc` to include the optional native RTC entry. That archive declares
the exact `werift@0.27.0` peer dependency; the default archive has no runtime
package dependencies and remains SQL-free.

`--sql-native` includes `/sql`, the thin native engine adapter and the exact
compiled addon. `--sql-browser` includes `/sql` and the verified browser
loader/factory without embedding an engine build. Both flags can be combined.
The packager checks that the common SQL and browser entries import no native
runtime even when the archive also contains the native adapter. Shared chunks
retain one session and one materializer class across all entries.
