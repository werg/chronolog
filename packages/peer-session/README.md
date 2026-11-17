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
schemas and semantic version. The event execution manifest is obtained with
`eventExecutionManifest('peer-generation-v1')`; a chronological manifest is a
different execution contract and is rejected.

Only first device setup passes `{ create: true }`. Ordinary reopening omits it.
The session owns one signed attempt journal in the device store. A disconnected
command remains `saved`; connecting resumes its exact original attempt.
Cancelling `applied({ signal })` cancels that waiter only.

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

The `/webrtc` entry provides `connectApplicationWebRtc(session, options)` for a
runtime with a usable RTC factory. The optional `/webrtc-native` entry supplies
`connectNativeApplicationWebRtc(session, options)` with the exact supported
Werift implementation. Returned connections expose logical frame byte counts,
request counts, and `rtc.getRoute()` observations. An unknown observed route
stays unknown.

In a browser, install `installApplicationWorkerTransport(session, self)` beside
the Worker-owned session. The page calls
`connectWorkerApplicationWebRtc(worker, { role, signaling, expectedPeerId })`.
The helper transfers both negotiated channels synchronously, owns the dedicated
control port, and waits for authentication and initial replay. The page retains
the peer connection for ICE lifecycle and route diagnostics. This API requires a
browser that supports transferring RTC data channels; unsupported browsers fail
explicitly. Actual browser qualification is separate from native stream tests.

A session with a selected recovery prefix that has not arrived reports
`status.phase === 'recovering'`. Queries fail with `PEER_RECOVERING` until a
complete verified prefix is materialized. Change subscriptions wait for that
first coherent view. Sessions permit at most eight simultaneously held read
views; release them promptly. Closing the session releases all remaining views
and connections before closing its durable store.

## Page facade

The Worker opens the device and owns the application. Installing its page facade
also owns the RTC channel transfer bridge:

```ts
import { serveApplicationWorker } from '@chronolog/peer-session/browser'

serveApplicationWorker(session, self, { host })
```

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
`applied()` and `shared()` can wait through an offline period until their signal
is aborted; they are not limited by the ordinary RPC request deadline. Query
results cross the bridge as plain records, arrays, scalar values, SQL bigints
and `Uint8Array` bytes. Class instances, key objects and shared memory are
rejected, and message budgets apply before posting.

The optional `host` stays in the Worker for `recovery.takeover()` and
`recovery.handover()`; ordinary commands do not call it. The bridge serves one
page facade, bounds pending requests and pulled streams, and releases held views
on close. `session.close()` resolves after the Worker has released the owned
device store, so the page can safely reopen it immediately afterward.

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
schemas from the same application definition. It exposes inspection, exact
retry, wait, recovery inspection and explicit reapplication. A host port enables
the takeover tool. `serveApplicationToolLines(session, { input, write, host })`
accepts bounded JSON lines such as
`{"id":1,"tool":"command","input":{"name":"say","input":{"text":"Hello"},"operationId":"message-1"}}`.
Use `tool: "list"` for schemas and `tool: "wait"` with the operation ID for its
current applied result. The transport creates no second identity, outbox, or
hosted command proxy.

## SQL composition

The portable and ordinary browser entries are SQL-free. SQL applications use
`openNativeSqlApplication` from `@chronolog/peer-session/sql-native` or
`openBrowserSqlApplication` from `@chronolog/peer-session/sql-browser`. Both
construct the same deterministic materializer under the owned device session,
verify the signed initializer and execution identity before creating a SQL
database, and close the materializer before releasing device storage.

The native constructor takes `databasePath` and the signed `schema` alongside
the usual `device`, `definition` and `authority` options.
`prepareNativeSqlApplication({ applicationId, definition, schemaAdministrator })`
returns that signed schema and the descriptor binding fields for the exact
compiled engine. The definition must contain its initializer in `schema`.

The browser constructor runs in the isolated owning Worker and takes `engineUrl`
instead of a database path. Serve the packaged `browser-engine` directory as
static assets with JavaScript/WASM content types and the same cross-origin
isolation policy as the Worker. The directory URL may include or omit its final
slash. For example:

```ts
import { openBrowserSqlApplication } from '@chronolog/peer-session/sql-browser'

const session = await openBrowserSqlApplication({
  device, definition, authority, schema,
  engineUrl: new URL('/chronolog-engine/', self.location.href),
})
```

The session verifies the engine bytes and manifest, opens an OPFS handle pool
scoped to the durable storage identity and application, and owns its lifetime.
`createBrowserSqlManifest(buildManifest)` exposes the matching execution
manifest for bootstrap. Native and browser peers must use that same signed
identity; an incompatible engine fails before initializing the SQL cache.
The database is derived from authenticated history. It does not replace the
original encrypted records, saved operation intent, or epoch keyring.
Irreversible effects require a separately declared protected boundary.

## Build a packed preview

Run `node tools/package-peer-session.mjs`. The tarball includes shared ESM chunks,
self-contained TypeScript declarations, and commit/tree/file-hash provenance.
`--allow-dirty` produces an explicitly marked development artifact. Native and
browser entries share session classes and ownership state through those chunks.
Use `--native-rtc` to include the optional native RTC entry. That archive declares
the exact `werift@0.27.0` peer dependency; the default archive has no runtime
package dependencies and remains SQL-free.

Use `--sql-native` for the native SQL entry and exact compiled patched addon.
That archive is bound to the build platform and architecture. Use
`--sql-browser artifacts/wasm` after `tools/build-wasm-engine.mjs` to include the
browser SQL entry and its four engine assets. The packaging gate checks the WASM
digest, source identity, deterministic hooks and runtime versions against the
native build, then records every asset hash in provenance. Combine both flags
when qualifying browser/native peers on the same execution profile.

`node tools/test-peer-session-sql.mjs --artifact /path/to/archive.tgz` installs
the native SQL archive into an empty independent project and exercises shared
rows, constraint rejection, generation recovery, creator departure and reopen
without workspace imports or install scripts.
