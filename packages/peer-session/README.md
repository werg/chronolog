# Peer application sessions

`@chronolog/peer-session` owns the application runtime. All participants use the
same signed protocol and participant contract. Identity, membership, code exchange
and live signals run immediately; the durable journal, replication, materializer
and query implementation load on actual data demand. `peer-generation-v1` identifies the signed record format; it is not
an application mode or a selector for a second implementation.
One eligible peer sequences commands. Ordinary commands, queries, history and
live signals need no control-service request while that generation is healthy.
Direct WebRTC carries peer traffic without a relay; the WebSocket fallback
forwards encrypted peer traffic through the relay. A signed
control service selects a successor during takeover. Recovery can abandon a
recent suffix, which remains inspectable and requires explicit reapplication.

An applied result is accepted or rejected at one generation and sequence. It is
stable in that history, but is not irreversible finality. This package exposes
no `final()` wait and no automatic external-effect dispatcher.

## Immediate protocol, data on demand

Opening an application starts its authenticated protocol participant. Reading
`status`, `revision`, `capabilities` or `describe()`, observing status/recovery,
registering a projection, connecting peers and exchanging control, publication
or live signal messages do not load database code or acquire data storage.
Authentication and membership use the participant's verified authority and its
small metadata store; they do not depend on a replica or materializer.

The first command, query, read view, operation inspection, content request,
recovery action or projection read loads the one durable implementation. Pulling
`changes()` also demands data; constructing the iterable does not. Concurrent
first uses share one initialization and one initial synchronization through
already connected peers. Later calls retain ordinary local-view semantics.
There is no separate initialization call, application mode or transport profile.

`status.database` reports `idle`, `opening`, `ready`, `failed` or `closed`.
`ready` means the durable owner exists; `status.phase` still describes whether
its selected history and keys are usable. `revision` is `null` before a coherent
data view exists. Queries and captured views return their own non-null revision.
A failed first initialization releases partial data resources and remains failed
for that session. The same authenticated participant can still exchange live
signals and control messages. Closing drains owned work and releases resources;
closing an unused browser session never opens a record data store.

Browser devices retain their small identity and verified-control metadata in
IndexedDB. On the **first actual data use**, an exclusive named Web Lock is acquired
and the local record backend is selected and pinned in metadata: OPFS when a real
createWritable/write/reopen probe succeeds, or a separate IndexedDB bytes store
for a fresh device when that OPFS write API is unsupported. The application's
signed protocol and all consumer APIs remain unchanged. SQL's OPFS/SQLite VFS
is **not** selected by this rule.

A pinned device never switches record backends automatically, even after a
browser update, quota failure or missing data. Existing OPFS records, including
possible legacy interrupted writes, must remain OPFS or fail explicitly; no
application history is copied, reset or forked. The lock is held until all
admitted writes and the record store are closed. Cold tabs can share one signer
without opening a data store, but a second concurrent durable owner receives
`BROWSER_STORAGE_IN_USE`. See [browser record compatibility](../../docs/browser-storage.md)
for capability diagnostics, failure behavior, and qualification boundaries.

## Native events application

Create or enroll a device explicitly before opening a session. Resuming a device
never replaces missing keys. The explicitly opened native store holds its SQLite
writer lock. Its application materializer is still deferred until data use.
Browser ownership follows the metadata/data boundary described above.

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

`await session.authority()` reads a cloned snapshot of the current public signed
`AuthorityBundle` already verified and retained by this session. It includes the
descriptor, controls/grants, and selected-generation evidence; it contains no
private signing or decryption keys. This works while the database is idle and
does not contact the control service or activate application storage. Use it for
membership and roster rendering, then combine it with separately observed live
presence. Mutating the returned object cannot change the owner's authority.
The Worker and attached native facades expose the same asynchronous method;
delegated attachments need the `diagnostics` capability. The snapshot describes
the last verified local authority and does not claim that an offline participant
has learned a newer remote revocation. Transport delivery and presence never grant
membership rights.

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
  createEngine: () => engine, device, definition, authority, schema: prepared.schema,
  databasePath: './application.sqlite',
})
```

Normal reopening reuses the published signed schema and existing device. It does
not sign a new schema. The common opening function claims device ownership before
constructing a materializer, verifies the schema authority and definition, and
requires the engine manifest to match the descriptor before opening a database.
The opening API captures the factory and signed schema immediately, invokes the
factory only on first data demand, and then captures its engine capability.
Normal reopen can dynamically import the native engine inside `createEngine`.
Closing the session
releases its SQL views and database handles through the same owned lifecycle as
event execution.

In an owning browser Worker, import and load the verified WASM engine inside
that same first-use factory:

```ts
const session = await openSqlApplication({
  device, definition, authority, schema, databasePath: '/application.sqlite',
  async createEngine({ signal }) {
    const { createBrowserSqlEngine, loadBrowserEngine } =
      await import('@chronolog/peer-session/sql-browser')
    const loaded = await loadBrowserEngine(engineAssetBaseUrl)
    signal.throwIfAborted()
    // Initialize the application's VFS provider here and retain its cleanup handle.
    return createBrowserSqlEngine({ ...loaded, vfs: ownedSqlVfsName })
  },
})
```

Chronolog closes SQL database handles through its durable data lifetime. The
application's VFS provider owns any OPFS pool and must release that pool after
those database handles close. `createEngine` returns an engine capability; it
does not transfer ownership of an externally supplied VFS. Native and browser
factories produce the same SQL execution
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
Signing a release requires an explicit `publisher` grant. Administration and
application-data access do not confer publication rights. The hosted control
participant serves approved releases without publisher or application-reader
rights; a publisher can sign portable release records without joining the data
session or obtaining its encryption keys.

## Durable derived views

Register pure event reducers in the owning native session or browser Worker:

```ts
const counts = session.project({
  id: 'message-count', version: '1', topics: ['message'], initial: 0,
  reduce: count => count + 1,
})
const snapshot = await counts.read()
// snapshot.state and snapshot.revision describe the same captured history.
for await (const next of counts.changes({ signal })) render(next.state)
```

The session persists reducer state, normalized topic filter, reducer version,
captured revision and verified event cursor in one atomic checkpoint. Ordinary
reads reduce only new matching events; an unchanged read does no checkpoint
write. Reopening the same projection resumes its durable cursor. Change the
version whenever reducer semantics or initial state change.

A generation change rebuilds from the selected history and returns
`reset: { reason: 'recovery', previousRevision }`. A changed version or topic
filter rebuilds with `reason: 'definition'`. The new state is visible only after
its complete checkpoint is durable. An excluded suffix never remains hidden in
a cumulative derived view. Coalesced change observations hold no captured view
while waiting for the next update.

The Worker registers reducers before serving its page facade. The page accesses
the same handle through `application.projection<number>('message-count')`, with
the same `read()`, `changes()` and `close()` operations. Reducer callbacks and
checkpoint storage stay in the owner. There is at most one open projection for
an ID, at most eight per session, and each JSON state is bounded to 512 KiB.

Reducer failures leave the last checkpoint intact and do not interrupt ordinary
application commands. A failed durable-write acknowledgment fences that
projection until it is closed and reopened; it does not invent successful
progress. Closing the session drains admitted checkpoint writes before releasing
storage. Cancelling a read only stops that caller's wait.

Reducers must not perform external effects. They may run again after recovery,
a definition change or an interrupted checkpoint. An external dispatch journal
must preserve provider outcomes independently and use an explicitly protected
action policy; ordinary applied events and projection progress supply no such
guarantee.

## Owned participation and recovery

Call `session.participate()` once after opening the session. It owns discovery,
invitations, authenticated peer connections, reconnect backoff and recovery policy.
The supplied ports deliver routing hints and raw framed connections; they cannot
declare a peer authorized or choose a recovery prefix.

```ts
import { createPeerIntroductions } from '@tendriller/core/peers'
import { openWebRtcConnection } from '@chronolog/peer-session/webrtc'
import { openWebSocketConnection } from '@chronolog/peer-session/websocket'

const participation = session.participate({
  control,
  ...createPeerIntroductions({
    peers: client.peers,
    identity: session.deviceId,
    openDirectConnection: options => openWebRtcConnection(options),
    openRelayConnection: ({ relay, signal }) =>
      openWebSocketConnection(relay, { ready: relay.ready, signal }),
  }),
  recovery: { graceMs: 3000, freshnessMs: 300_000 },
})
participation.onStatus(status => renderParticipation(status))
// After presenting the current proposal and obtaining the user's decision:
await participation.approveRecovery(proposal.id)
```

A native process supplies an RTC factory through its raw opener. A browser
Worker uses `openWorkerWebRtcConnection(self, options)` as shown below. The same
controller and authenticated protocol run in both environments. The introduction
attempt tries the direct connection for a bounded interval, then opens two relay
WebSockets on the same invitation channel. It returns one raw connection to the
session. The session owns authentication, synchronization and every later retry;
transport fallback creates no second operation journal or recovery controller.
WebSockets are available in the owning Worker directly and need no page bridge.

The default controller owns at most four connections, with a hard maximum of
eight. Attempts have a 15-second deadline and bounded exponential backoff with
jitter, starting at one second and capped at 30 seconds. A transport that ignores
cancellation continues to occupy its bounded opening slot; a late connection is
closed rather than attached. Discoverability leases renew every 60 seconds.
Healthy peers synchronize on that coarse cadence, and directory reads occur
only while the graph is underfilled or the coordinator is absent. Ordinary
commands and live signals do not cause control-service requests. A relayed
connection does carry their ciphertext through its WebSockets.

After coordinator loss, the controller first gives reconnection its configured
grace. It verifies the current signed authority and synchronizes reachable peers
before considering a successor. Peers with a failed synchronization are retired
and retried; old retention alone does not establish current reachability.
Candidate selection uses the complete best
prefix actually verified locally on the selected ancestry. A remote successor
must hold a signed retention acknowledgment for that exact prefix; a self
candidate must validate and replay its complete prefix. If newer inherited
segments are unavailable, a survivor can propose the last fully retained ancestor
whose selected cutoff is provable. An empty survivor or partial segment without
its receipt bridge cannot supply that evidence. Current coordinator and recovery grants are
checked independently, and the candidate must hold the key committed by the active
control epoch. Current-generation retention acknowledgments require that same key;
a peer still acquiring it returns no coverage while its enrollment connection remains
available. Directory hints, advertised eligibility and remote
retention timestamps supply no authority or freshness evidence.

Automatic selection additionally requires recent local evidence from an
authenticated coordinator head request whose complete prefix was verified.
The durable timestamp is the start of that request, so transfer delay cannot
make old evidence appear newer. Evidence from a different generation, a future
local timestamp or an excluded prefix does not qualify. This observation budget
is a conservative recovery policy, not an unconditional loss guarantee: host
outages, suspension and long disconnection can leave freshness unknown or older
than the budget. Such cases expose `phase: 'approval-required'` with the exact
complete prefix, candidate, observation age and reason. Only approving that
proposal ID permits the broader recovery; changed authority or prefix invalidates
the choice, including changes during the final host refresh before signing.
While that ancestor is proposed or approved, current reads remain recovering and
projections do not reset. Only selecting and materializing the successor publishes
the adopted prefix. Protected recovery floors still apply.

The controller uses the existing durable transition journal. Lost takeover and
handover replies retry the same signed request, and competing valid selections
are resolved by the host CAS. Host unavailability leaves ordinary commands saved
in their original journal until a usable coordinator is available. Reconnection
resumes eligible original attempts. A generation change marks excluded saved
attempts `needsReapply`, requiring an explicit new operation instead of silently
changing their signed meaning. There is no second application queue.

`session.participation` exposes the one handle for the session's lifetime.
`participation.close()` fences timers, pending replies and invitations, closes
its peer connections and attempts a bounded lease withdrawal. The closed handle
remains inspectable; starting a second controller is rejected. Closing the
session also closes participation before releasing its durable store.
Control reads and selections carry the operation's cancellation signal, so a late
reply cannot mutate a closed controller's session. An already dispatched selection
may still commit remotely; its saved exact request remains available for recovery.

## Enrollment and epoch keys

The device owns one Ed25519 identity. Its durable application keyring opens
with the data facet. An initial creator passes `epochKeys` to the open function
as explicit local bootstrap; normal first data use loads enrolled keys from
the owned store. A newly granted reader can authenticate and exchange live or
control messages without epoch keys. After data activation it reports
`status.phase === 'awaiting-keys'` until another current reader supplies the
needed keys through an authenticated connection.

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
reading retained history and content. Explicit `session.keys.request()`,
`offer()`, `install()`, `ensure()` and `missing()` calls are asynchronous data
demands. The maintained connection owner attaches key sources to the same
authenticated peer link when the durable facet becomes active.

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
lanes (`send`, `frames`, `signal`, `close`) and an optional separate disposable
`live` lane. `openWebRtcConnection()` and `openWebSocketConnection()` implement
this structural interface directly, in a native process or an owning
browser Worker. A discovery result identifies a possible route; the session
independently verifies a fresh signed challenge bound to both identities, the
application descriptor, and the signed record format before attaching that route.
An optional `peerIdentity` pins the discovered identity. A control-only host
identity cannot attach without an explicit reader grant.
The hello can carry a newer signed authority bundle, so an existing reader can
verify a newly enrolled peer's grant before checking its proof of possession.

Every transport uses the same authenticated encrypted channel. Signed hello
transcripts bind the application, both identities, fresh ephemeral receiver keys
and the selected cipher suite. RFC 9180 HPKE exports distinct traffic keys and
nonces for each direction and lane. AES-GCM protects every subsequent reliable
frame and live signal; reliable sequences reject replay or gaps, while disposable
traffic may lose frames and drops stale sequence numbers. Channel keys expire at
bounded byte and record counts and renew through the existing reconnect owner.
The relay sees public handshake authority, packet sizes and timing. It receives
no channel keys or application plaintext and obtains no application-reader grant.

The returned link exposes `peerId`, `signal`, `completion`, `synchronize()` and
`close()`. History requests select one advertised head and check each original
signed command before retaining its ciphertext and replaying it. Retention proofs
refer to an exact locally held prefix. Both directions exchange available history,
including when a fresh device is still recovering an inherited generation.
Explicit synchronization observes a fresh head after any older background pull.
Local history/control changes trigger coalesced peer hints. Owned participation
adds coarse discoverability renewal and peer synchronization, without an
application-data HTTP fallback. Pending commands use the session's
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

Signed live signals use only the optional disposable lane and its independent bounded
queue. Congestion drops live traffic before dispatch; it never enters the durable
history queue. Live signal authors and connected peers must remain current
readers. Command submission and ordering additionally recheck current writer
permissions. Reader removal retires the peer connection.

The initial creator provisions its epoch key explicitly. Maintained connections
acquire a granted reader's missing keys through the authenticated keyring port;
each share is HPKE-wrapped for that device's fresh signed request. The request's
recipient and the share's issuer must match their authenticated peer connection.
Keys are never sent in plaintext. The same authenticated key exchange operates
over either physical transport, inside the shared encrypted peer channel.

`connectApplications(a, b)` is a built-in in-process transport for embedded peers
and independent-store qualification. It executes this same authenticated framed
protocol over bounded memory byte lanes, including live signals. It is not a
measurement of Internet WebRTC routing. No recipe needs its own application retry
queue.

The lower-level `session.recovery.takeover(host, { transitionId })` validates this device's
complete recovery point, saves one signed transition request, selects it through
the host, and adopts the verified result. Retry the same transition ID after a
lost hosted reply, including after device reopen. For an inherited recovery base,
`expected.generation` names the current selected generation for the control CAS,
while `expected.point.generation` names the ancestor containing the displayed
complete prefix. Both remain bound to the saved request. A planned
`session.recovery.handover(host, { coordinator, transitionId })` additionally
requires a complete current view and the successor's signed retention of that exact prefix. These
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
Werift implementation. Application links expose encoded application-wire byte
and request counts. These byte counts precede channel encryption; physical
transport statistics include encrypted frame payloads, and relay reports account
for relay traffic separately. `rtc.getRoute()` observes the selected ICE route.
An unknown observed route stays unknown.

The `/websocket` entry supplies `openWebSocketConnection({ reliable, live },
options)`. It attaches both binary readers synchronously, waits for optional
transport admission and the common framing handshake, then returns one owned
connection. `frameWebSocketPeerConnection()` exposes the same connection and its
`ready` promise when a transport needs to install readers before admission ends.
Both WebRTC and WebSocket use the shared reliable fragment/credit implementation
and shared disposable queue. Only physical socket readiness and writable-buffer
notifications differ.

The relay uses separate WebSockets for reliable and live frames. Live traffic
never waits behind application history and is refused before dispatch when its
socket is congested; it is not retried. Once dispatched, WebSocket traffic has
TCP delivery semantics, so delayed live records still rely on the common signal
expiry checks. Relay admission and recipient receipts bound host forwarding
buffers without inspecting application records. A relay outage ends relayed
connections; exact saved commands resume through ordinary participation when a
route becomes available. Direct connections can continue without the relay.
TURN is not required by this fallback architecture.

In a browser, the page serves `serveWorkerWebRtcConnections(worker)`. The owning
Worker calls `openWorkerWebRtcConnection(self, options)` through its raw transport
opener. The Worker owns discovery, signaling and recovery policy; the page performs
RTC negotiation and synchronously transfers both negotiated channels back. The
common session then authenticates the connection and verifies the selected
history. The page retains the peer connection for ICE lifecycle and route
diagnostics. This API requires a
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
qualify hosted enrollment, automatic key delivery or public network traversal.

A session with a selected recovery prefix that has not arrived reports
`status.phase === 'recovering'`. Queries fail with `PEER_RECOVERING` until a
complete verified prefix is materialized. Change subscriptions wait for that
first coherent view. Sessions permit at most eight simultaneously held read
views; release them promptly. Closing the session releases all remaining views
and connections before closing its durable store.

## Page facade

The `/worker` entry opens the device and owns the immediate protocol participant;
its durable facet remains lazy. The `/browser` entry contains only the page
facade and shared RPC contracts. Configure participation
before serving the facade so the page receives its stable status and approval
handle:

```ts
import { openBrowserDevice, openBrowserApplication, serveApplicationWorker } from '@chronolog/peer-session/worker'
import { openWorkerWebRtcConnection } from '@chronolog/peer-session/webrtc'
import { openWebSocketConnection } from '@chronolog/peer-session/websocket'
import { createPeerIntroductions } from '@tendriller/core/peers'

const device = await openBrowserDevice({ name: 'conversation', create: true })
const session = await openBrowserApplication({ device, definition, authority })
const control = session.connectControlParticipant({
  exchange: (request, { signal }) => client.peers.exchange(request, { signal }),
})
session.participate({
  control,
  ...createPeerIntroductions({
    peers: client.peers, identity: session.deviceId,
    openDirectConnection: options => openWorkerWebRtcConnection(self, options),
    openRelayConnection: ({ relay, signal }) =>
      openWebSocketConnection(relay, { ready: relay.ready, signal }),
  }),
})
serveApplicationWorker(session, self, { host: control })
```

The page facade and RTC delivery use separate message namespaces. The RTC helper
is optional when the application does not use RTC.

The page connects through a dedicated message port:

```ts
import { connectApplicationWorker } from '@chronolog/peer-session/browser'
import { serveWorkerWebRtcConnections } from '@chronolog/peer-session/webrtc'

const rtc = serveWorkerWebRtcConnections(worker)
const session = await connectApplicationWorker<typeof definition>(worker)
const before = await session.query('messages', null)
const operation = await session.command('say', { text: 'Hello' }, {
  operationId: crypto.randomUUID(), basedOn: before.revision,
})
const result = await operation.applied()
```

The returned `WorkerApplicationSession` provides the same declared commands,
queries, operation inspection, retry, explicit reapplication, changes, live
signals and content handles. `status` and nullable `revision` are synchronous snapshots;
`describe()` returns the application contract. `onStatus()` and `onRecovery()`
observe updates, while `inspectRecovery()` loads retained recovery notices.
If the Worker configured participation, `session.participation` exposes its
`status`, `onStatus()`, `approveRecovery()` and `close()` without moving policy or
credentials into the page.
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
schemas from the same application definition. Command and reapplication schemas
accept an optional `basedOn` revision returned by a coherent query. The complete
revision shape is also used by `changes`; its application and history scope are
validated before use. A revision guard does not replace domain transaction guards.
The tools share operation inspection, exact retry, wait, recovery inspection and
explicit reapplication. A host port enables the takeover tool.

`operation` and `wait` accept an optional `author` public key; omitting it selects
this device's operation. Operation IDs are scoped to their actual signer, so
another participant can use the same ID without changing which command is read.
`reapply` accepts `originalAuthor` to identify another participant's retained
abandoned work. The replacement is signed by the current device under its
current permissions and links to the original attempt. `retry` remains scoped
to this device's exact saved bytes. Native and Worker `operations.wait(id,
{ author, signal })` use the same author scope.

`changes({ after?, waitMs? })` observes at most one coalesced coherent change from
`session.changes()`. Without `after` it returns the current ready revision; with
an unchanged revision it waits for at most `waitMs` (0 by default, maximum 30,000
milliseconds). The result is `{ change, resetRequired }`; `change: null` means
no newer ready view was observed within that interval. A generation difference
sets `resetRequired: true`, including when the observer starts after recovery.
When available, the result includes the actual recorded recovery notice. An
unknown notice never becomes an invented abandoned range or loss estimate.
Reread coherently after a reset and use `recoveries` for retained recovery
history. This observation is an invalidation, not a complete event log or durable
cursor. Timeout, caller cancellation and session close release the iterator.

`serveApplicationToolLines(session, { input, write, host })` accepts bounded JSON
lines such as
`{"id":1,"tool":"command","input":{"name":"say","input":{"text":"Hello"},"operationId":"message-1"}}`.
Use `tool: "list"` for schemas, `tool: "wait"` with an operation ID for its applied
result, or `tool: "changes"` with the captured revision as `input.after` for a
bounded observation. Set the request's `timeoutMs` above `input.waitMs` when a
normal unchanged result is wanted. The transport creates no second identity,
watcher queue, outbox or hosted command proxy.

The portable, page, Worker and common SQL entries load no database implementation
eagerly. SQL applications supply a lazy engine factory through the same execution
contract; the pinned schema
is initialized before application history. Irreversible effects require a
separately declared protected boundary.

## Build a packed preview

Run `node tools/package-peer-session.mjs`. The tarball includes shared ESM chunks,
self-contained TypeScript declarations, and commit/tree/file-hash provenance.
The `runtimeModules` provenance map records each emitted module's contributing
source files and import edges so downstream builds can verify actual requested
code against the lazy boundary.
`--allow-dirty` produces an explicitly marked development artifact. Native and
browser entries share session classes and ownership state through those chunks.
Use `--native-rtc` to include the optional native RTC entry. That archive declares
the exact `werift@0.27.0` peer dependency; the default archive has no runtime
package dependencies and remains SQL-free.

`--sql-native` includes `/sql`, the thin native engine adapter and the exact
compiled addon. `--sql-browser` includes `/sql` and the verified browser
loader/factory without embedding an engine build. Both flags can be combined.
The packager checks the actual emitted static import closure of `/`, `/browser`,
`/worker`, `/tendriller` and `/sql`: none may load a replica, materializer, content
owner, projection owner or OPFS implementation before a dynamic data demand.
It also checks that browser entries import no native runtime even when the archive
contains the native adapter. Shared chunks
retain one session and one materializer class across all entries.

## Multiple local clients, one session owner

The owner/attachment protocol is `chronolog/peer-session/owner/v2`. It is independent
of the immutable application definition and selected history generation. The
existing dedicated `serveApplicationWorker` / `connectApplicationWorker` pair is
still a single-client lifetime; use the owner API for concurrent tabs or tools.

```ts
// Worker entrypoint: acquire protocol ownership before opening profile identity.
import { acquireApplicationOwnerLock, createApplicationOwner } from '@chronolog/peer-session/worker';
const lease = await acquireApplicationOwnerLock(retainedProfileId);
const session = await openTheRetainedApplication();
const owner = createApplicationOwner(session, {
  lastClient: 'keep-alive',
  prepareCommand(endpoint, name, input) {
    return bindApplicationSource(input, endpoint); // Optional product validation.
  },
});
// SharedWorker: every onconnect port accepts isolated application attachments.
self.onconnect = event => owner.attach(event.ports[0]);
// On deliberate shutdown: await owner.close(); await lease.close();
```

```ts
import { connectApplicationOwner } from '@chronolog/peer-session/browser';
const attached = await connectApplicationOwner(sharedWorker.port, {
  applicationId, definitionId: definition.id, definitionVersion: definition.version,
  context: { viewId: retainedViewId, documentPath: '/review.html', publicationId },
});
const actualViewId = attached.endpoint.context.viewId;
await attached.command('review', input, { operationId: retainedOperationId });
await attached.detach(); // Does not close the session, journal, or sibling clients.
```

One owner allocates a fresh endpoint ID and incarnation for each exact port. The
owner supplies these fields on live signals and passes them to its optional command
composition callback. A caller cannot choose another endpoint ID. Document, run and
publication context is marked `caller-asserted` unless the trusted owner policy
validates it. A duplicated live `viewId` receives a new view ID; after detach the
original view can be deliberately restored with a new endpoint incarnation.
`endpoint.suspend` and `resumeAttachment` preserve the incarnation only while that
exact original binding survives. A replaced port must reconnect and reconcile its
original operation references.

Each attachment has its own RPC IDs, cancel scopes, captured views, projection
handles and bounded streams. Bad frames and detach dispose only that attachment.
Projection close releases the caller's handle and streams without closing the
owner's shared projection registration. Ordinary clients cannot adopt authority,
recover, close participation, or shut down the owner. A trusted `owner.attach(port,
{ capabilities: [...] })` or `authorize(handshake)` policy can grant ownerAdmin,
restrict declared commands/queries, and set smaller quotas; client metadata never
grants capabilities. Query restrictions should omit `events`/`content` when raw
reads must be unavailable. These are same-profile delegation controls, not a
sandbox between mutually hostile scripts sharing one origin and signer.

Default bounds are 32 attachments, 16 active requests / 8 streams / 8 held views
per attachment, and 512 requests / 256 streams / 128 views across the owner.
Releases, cancellation and detach retain cleanup capacity when passive waiters fill
ordinary admission. Congestion rejects explicitly before dispatch instead of
creating another command queue. Configure the session's signal subscription budget
to match the chosen profile. `signals: { localEcho: true, limits:
{ maxSubscriptions: 256 } }` permits local live fan-out without requiring a remote
peer. Attaching, status observations, endpoint inspection, and signals leave the
application database lazy; a data read or command opens it once.

The lightweight `chronolog-owner:<profileId>` Web Lock is separate from the real
`chronolog:<profileId>` durable storage lock. Neither is stolen after a heartbeat
or suspension timeout. Hold the owner lease until session shutdown has released
its resources. A failed acquisition returns `OWNER_BUSY`; missing Web Locks returns
`APPLICATION_OWNER_LOCK_UNAVAILABLE`. Do not create a replacement signing identity
as a fallback. `wait: true` queues a cancellable takeover behind actual lock release,
without guessing failure from a timer. SharedWorker and elected-context compositions must negotiate one
compatible immutable owner artifact and use the same profile lease; transport/RTC
host handoff remains an explicit product composition responsibility.

### Guarding work across generations in SQL

The SQL runtime supplies a reserved, read-only `chronolog_execution_context` row
while a verified attempt executes. It contains its actual transaction ID,
application ID and original signed generation. Application triggers can use:

```sql
SELECT chronolog_assert(
  NEW.generation IS (
    SELECT lower(hex(generation)) FROM chronolog_execution_context
    WHERE singleton = 1 AND transaction_id = chronolog_transaction_id()
  ), 'claim_generation_mismatch'
);
```

Guard completion against both the claim's stored generation and that current
attempt context. An inherited claim still has its old fence after a generation
transition, so completing it requires an explicit guarded rebind/reassignment.
Historical replay validates it under its original generation. The peer history
owner supplies authenticated attempt-generation mappings; command payloads never
supply this execution context. Ordinary writers cannot mutate the context,
retained `chronolog_attempt_generations`, or application triggers. The context row
is cleared before publication; retained generation evidence prevents changing an
existing attempt's interpretation. This changes the SQL execution manifest and
requires a fresh compatible application/schema tuple; it does not silently migrate
old SQL stores or grant exclusive execution to events-only projections.
