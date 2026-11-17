# Peer application sessions

`@chronolog/peer-session` exposes the `peer-generation-v1` application profile.
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
  openApplicationSession, type ApplicationReadView } from '@chronolog/peer-session'
import { openNativeDevice } from '@chronolog/peer-session/native'
import { maintainNativeApplicationWebRtc } from '@chronolog/peer-session/webrtc-native'

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
// One-time device/application setup. Ordinary reopening omits both create flags.
const device = await openNativeDevice({ path: './device.sqlite', create: true })
const session = await openApplicationSession({
  device, definition, applicationId, host: client.peers, create: {},
})
const network = maintainNativeApplicationWebRtc(session, { host: client.peers })
try {
  await network.ready
  const before = await session.query('messages', null)
  const operation = await session.command('say', { text: 'Hello' }, {
    operationId: crypto.randomUUID(), basedOn: before.revision,
  })
  const result = await operation.applied()
  console.log(result.generation, result.sequence, result.outcome)
} finally { await network.close(); await session.close() }
```

`applicationId` is the selected hosted application's ID, and `client.peers` is
the public Tendriller client control/discovery port. First publication durably
saves its random epoch key, immutable configuration and signed initial selection
before sending them. Lost configuration or generation-selection replies reuse
those exact records after device reopen. The host receives the key commitment,
public schemas and signed controls; it never receives the plaintext epoch key.

Omit the application `create` option to join an existing application after the
administrator grants this device's public key. A new reader acquires wrapped
keys from an authenticated current reader before replay. Its keys and verified
application binding remain in the owned device store. Reopening the same device
with `openApplicationSession({ device, definition, applicationId })` uses that
cached binding without a hosted request. The maintained network learns newer
signed controls on join/reconnect and through authenticated peer connections.

`applicationDefinitionDigest(definition)` binds the published schemas and
semantic version. The event execution manifest is
`eventExecutionManifest('peer-generation-v1')`; a chronological manifest is a
different execution contract and is rejected. The lower-level
`openPeerApplication({ device, definition, authority, epochKeys? })` accepts an
explicit verified binding and optional bootstrap seed for embedded integrations.

Only first device setup passes `{ create: true }`. Ordinary reopening omits it.
The session owns one signed attempt journal in the device store. A disconnected
command remains `saved`; connecting resumes its exact original attempt.
Cancelling `applied({ signal })` cancels that waiter only.

## Enrollment and epoch keys

The device owns one Ed25519 identity and one durable application keyring.
`openApplicationSession` creates and persists the initial key during explicit
first publication; normal reopening loads it from the owned store. A newly
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

`connectApplications(a, b)` is a built-in in-process transport for embedded peers
and independent-store qualification. It carries commands, verified history,
retention acknowledgments and signed live signals. It is not a measurement of
Internet WebRTC routing. No recipe needs its own application retry queue.

`session.recovery.takeover(host, { transitionId })` validates this device's
complete recovery point, saves one signed transition request, selects it through
the host, and adopts the verified result. Retry the same transition ID after a
lost hosted reply, including after device reopen. A planned
`session.recovery.handover(host, { coordinator, transitionId })` additionally
requires the successor's signed retention of the exact current prefix. These
methods never reinterpret an excluded branch as an eligible recovery base.

## Peer connections and Worker ownership

`connectApplicationTransport(session, { connection, expectedPeerId })` owns the
signed challenge handshake, bounded requests, captured history ranges and
retention acknowledgments over a framed reliable connection. Its optional live
lane carries disposable signed signals independently. Each side must call this
function; close or cancellation fences pending responses.

`connection.synchronize()` finishes one captured prefix. Later change hints
coalesce into a separate pass, so a continuously writing coordinator cannot
extend an earlier wait indefinitely. Ranges contain at most 32 commands and
fit the 1 MiB frame limit; verified pages are retained before requesting the
next page. The replica's configured record and history-byte quotas bound the
complete history. There is no smaller whole-history network buffer limit.
The selected view is published only after the captured root is available, and
the retention acknowledgment names that captured prefix. If recovery excludes
the captured generation during transfer, the pass fails explicitly; reconnect
or synchronize against the newly selected history. The lower-level replica
accepts command arrays or an async iterable of bounded command pages through
`synchronize(authority, commands, { at: capturedRevision })`.

A congested live lane refuses the current send without queuing it or closing
the reliable connection. Ending that lane retires its live route. A dispatched
write that ignores cancellation retires the physical connection, preventing
late work from surviving into its replacement. Connecting the same authenticated
peer again closes its previous connection. Signal sends always use routes
available when that attempt began; reconnecting never replays missed signals.

The supported lifecycle is `maintainNativeApplicationWebRtc(session, { host })`
from `/webrtc-native`, or `maintainApplicationWebRtc` with a browser-compatible
RTC factory. It owns bounded discovery, targeted invitation listening, SDP
rendezvous, authenticated catch-up, reconnect and eligible takeover. Directory
hints select routes; signed controls decide membership and generation authority.

Healthy connections do not consult the host for commands. Availability leases
renew coarsely, by default at the server's refresh point within a ten-minute
lease. An invitation listener has bounded backoff and an explicit stopped state;
its failure does not close established data connections. `network.reconnect()`
restarts an exhausted budget. Recovery defaults to a three-second observation
grace and a thirty-second takeover cooldown; a current complete eligible peer
still needs the control service to select a successor. Missing keys or an
incomplete selected prefix never qualify as a takeover base.

The `/webrtc` entry provides `connectApplicationWebRtc(session, options)` for a
runtime with a usable RTC factory. The optional `/webrtc-native` entry supplies
`connectNativeApplicationWebRtc(session, options)` with the exact supported
Werift implementation. Returned connections expose logical frame byte counts,
request counts, and `rtc.getRoute()` observations. An unknown observed route
stays unknown.

In a browser, the Worker owns the device and session. The maintained page facade
owns application calls and both-channel RTC handoff; its separate host bridge
uses the page's existing signed-in host connection for bootstrap and recovery.
The page owns discovery and negotiation. Keys, command preparation, materialized
views and durable work stay in the Worker. The complete composition is below.

For an already negotiated signaling route, the lower-level
`connectWorkerApplicationWebRtc(worker, { role, signaling, expectedPeerId })`
transfers both channels synchronously and waits for authentication and initial
replay. `installApplicationWorkerTransport` remains the transport-only owner
for integrations that deliberately omit the page application facade; do not
install it beside `serveApplicationWorker`. Transfer requires browser support
for transferable RTC data channels; unsupported browsers fail explicitly.
Actual browser qualification is separate from native stream tests.

`status.phase === 'awaiting-keys'` identifies a granted reader that still needs
peer-held decryption keys. A session with a selected recovery prefix that has not arrived reports
`status.phase === 'recovering'`. Queries fail with `PEER_RECOVERING` until a
complete verified prefix is materialized. Change subscriptions wait for that
first coherent view. Sessions permit at most eight simultaneously held read
views; release them promptly. Closing the session releases all remaining views
and connections before closing its durable store.

## Page facade

The page exposes its existing `runtime.host.peers` through the bounded host
bridge, then connects the application facade and maintained peer lifecycle:

```ts
import { connectApplicationWorker, serveApplicationWorkerHost } from '@chronolog/peer-session/browser'
import { maintainWorkerApplicationWebRtc } from '@chronolog/peer-session/webrtc'

const worker = new Worker(new URL('./application.worker.ts', import.meta.url), { type: 'module' })
const hostBridge = serveApplicationWorkerHost(worker, runtime.host.peers)
const session = await connectApplicationWorker<typeof definition>(worker)
const network = maintainWorkerApplicationWebRtc(session, worker, { host: runtime.host.peers })
await network.ready
```

The Worker waits for that control port before opening the application. This
example performs first setup; ordinary reopening omits both `create` options:

```ts
import { openApplicationSession } from '@chronolog/peer-session'
import { connectApplicationWorkerHost, openBrowserDevice, serveApplicationWorker } from '@chronolog/peer-session/browser'

const host = await connectApplicationWorkerHost(self)
const device = await openBrowserDevice({ name: 'conversation', create: true })
const session = await openApplicationSession({ device, definition, applicationId, host, create: {} })
serveApplicationWorker(session, self, { host })
session.signal.addEventListener('abort', () => { void host.close() }, { once: true })
```

The host bridge forwards only application lookup, definition lookup, immutable
configuration and signed generation selection. It carries no signing keys,
epoch keys, account credentials, commands or content. Its dedicated port bounds
calls and JSON bytes; cancelling a host observation leaves the Worker journal's
exact retry identity intact. Account authentication remains on the page's
existing host connection, so a signed-in browser does not need an agent token.

The page uses declared commands and queries:

```ts
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
`applied()` and `shared()` can wait through an offline period until their signal
is aborted; they are not limited by the ordinary RPC request deadline. Query
results cross the bridge as plain records, arrays, scalar values, SQL bigints
and `Uint8Array` bytes. Class instances, key objects and shared memory are
rejected, and message budgets apply before posting.

The optional Worker-side `host` handles `recovery.takeover()` and
`recovery.handover()` through that same control port; ordinary commands do not call it. The facade serves one
page owner, bounds pending requests and pulled streams, and releases held views
on close. `session.close()` resolves after the Worker has released the owned
device store, so the page can safely reopen it immediately afterward. On page
retirement, await `network.close()` and `session.close()`, then call
`hostBridge.close()` and `worker.terminate()`.

The `/tendriller` entry exports `createPeerGenerationApplicationBackend()` for
binding either an owned native session or this page facade to Tendriller's
application interface. It forwards declared commands and coherent views to the
same session instead of introducing another identity or queue.

## Content and local agent tools

`session.content.stage({ bytes, mediaType })` returns an upload handle with
bounded `write(index, bytes)`, `progress()` and `commit()` methods. `resume(id)`
reopens an interrupted upload. Only a complete upload produces a content
reference. References and encrypted 64 KiB chunks are separate from command
history. Readers fetch missing chunks from authenticated peers, verify them,
and retain verified chunks for bounded resumption.

`content.read(reference, { offset, length, signal })` yields plaintext chunks.
`content.retain(reference)` fetches the complete object and sends a signed
durable-copy observation to available sources. `content.retention(reference)`
reports those observations. Missing content returns `CONTENT_UNAVAILABLE`
without invalidating the application history that refers to it. Current read
permissions are rechecked at every fetch; a reference is never a credential.

`createApplicationTools(session, { host })` derives local query/command tool
schemas from the same application definition, including optional `basedOn`
revision guards. It exposes inspection, exact retry, wait, coherent change
observation, recovery inspection and explicit reapplication. The `changes` tool
accepts an optional `after` revision and returns one newer coalesced observation;
a generation reset explicitly requires rereading. Cancelling its wait does not
cancel any saved command. A host port enables
the takeover tool. `serveApplicationToolLines(session, { input, write, host })`
accepts bounded JSON lines such as
`{"id":1,"tool":"command","input":{"name":"say","input":{"text":"Hello"},"operationId":"message-1"}}`.
Use `tool: "list"` for schemas and `tool: "wait"` with the operation ID for its
current applied result. The transport creates no second identity, outbox, or
hosted command proxy.

For a standard local MCP connection, `serveApplicationMcpLines` serves JSON-RPC
over newline-delimited stdin/stdout using those same tools and saved operations:

```ts
import { createInterface } from 'node:readline'
import { serveApplicationMcpLines } from '@chronolog/peer-session'

await serveApplicationMcpLines(session, {
  input: createInterface({ input: process.stdin, crlfDelay: Infinity }),
  write: line => { process.stdout.write(line) },
  host: client.peers,
})
```

It supports initialization, tool discovery, tool calls and request cancellation,
with bounded requests and messages. A custom transport can use
`createApplicationMcpServer(session, { host })` and its `handle`/`close` methods.
The MCP adapter shares the application identity, declared input schemas,
revision guards, recovery journal and command journal. Cancelling an applied or
change observation leaves previously saved work available for inspection and
exact retry.

## SQL applications

The portable and `/browser` entries remain SQL-free. A native SQL application
uses `openNativeSqlSession({ device, definition, applicationId, host, create: {},
databasePath })` from `/sql-native`. Its literal `definition.schema` is signed
by the creating device and pinned in the application descriptor; the helper
prepares that envelope, publishes it and initializes the protected genesis.
Ordinary lossy commands cannot perform schema or permission changes. Joining or
reopening omits `create` and uses the published or cached schema. Reopening also
omits `host` when the device has a cached verified binding.

Browser SQL uses `openBrowserSqlSession({ device, definition, applicationId,
host, create: {}, engineUrl })` from the optional `/sql-browser` entry inside the
isolated owning Worker. As in native SQL, omit `create` for joining or reopening.
Serve the packaged `browser-engine` directory as static assets with
JavaScript/WASM content types and the same cross-origin isolation policy as the
Worker. The engine directory URL may include or omit its final slash. The
session verifies the engine bytes and execution identity before opening its
OPFS pool, scopes the database to the device and application, and waits for the
pool to release its handles before closing device storage. Both SQL paths authenticate the same
peer-generation engine profile. `prepareApplicationSession` and the explicit
SQL openers remain available for custom engine/provider composition; callers do
not implement control signing or bootstrap retry journals.

Shared SQL rows can use `APPLICATION_COLLECTIVE_ID` ownership when the domain
permits every currently authorized application member to edit them. Signed
controls define its current data roles, so creator departure does not freeze
shared data and data-role revocation survives history rollback. Private row
ownership remains tied to its actual author. Irreversible effects require a
separately declared protected boundary.


## Build a packed preview

Run `node tools/package-peer-session.mjs`. The tarball includes shared ESM chunks,
self-contained TypeScript declarations, and commit/tree/file-hash provenance.
`--allow-dirty` produces an explicitly marked development artifact. Native and
browser entries share session classes and ownership state through those chunks.
Use `--native-rtc` to include the optional native RTC entry. That archive declares
the exact `werift@0.27.0` peer dependency; the default archive has no runtime
package dependencies and remains SQL-free.

Use `--sql-native` to include the exact compiled native SQL engine and the
`/sql-native` entry. Its provenance records the engine manifest, patch digest,
platform and architecture. Qualify that artifact on the intended native target;
a native result does not establish browser/WASM or deployed-network behavior.

Use `--sql-browser artifacts/wasm` after `tools/build-wasm-engine.mjs` to include
the browser SQL entry and its four engine assets. The packaging gate checks the
WASM digest, source identity, deterministic hooks and runtime versions against
the native build, then records every asset hash in provenance. Combine it with
`--sql-native` when qualifying browser/native peers on the same execution profile.

`node tools/test-peer-session-sql.mjs --artifact /path/to/archive.tgz` installs
the native SQL archive into an empty independent project and exercises shared
rows, constraint rejection, generation recovery, creator departure and reopen
without workspace imports or install scripts.
