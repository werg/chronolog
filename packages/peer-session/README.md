# Peer application sessions

`@chronolog/peer-session` exposes the `peer-generation-v1` application profile.
One eligible peer sequences commands. Ordinary commands, queries, history and
live signals need no hosted request while that generation is healthy. A signed
control service selects a successor during takeover. Recovery can abandon a
recent suffix, which remains inspectable and requires explicit reapplication.

`operation.applied()` reports the accepted or rejected result at one selected
generation and sequence. `operation.shared()` separately observes an independent
peer's retained copy. Ordinary commands do not wait for that second copy, and
neither result prevents an explicit recovery from abandoning a recent suffix.
The current API uses these two names throughout sessions, tools and adapters.
External-effect dispatchers need a separate supported recovery contract; the
session does not install or trigger one automatically.

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

## Native SQL application

The optional `/sql-native` entry uses the pinned native DoltLite materializer.
Define the literal initializer in `definition.schema`, then use the canonical
session opener for creation, joining and offline reopening:

```ts
import { openNativeSqlSession } from '@chronolog/peer-session/sql-native'

const session = await openNativeSqlSession({
  device, definition, applicationId, host: client.peers, create: {},
  databasePath: './application.sqlite',
})
```

The creating device signs the initializer, and the opener owns publication,
initial key enrollment and exact generation-selection retries. Joining or
reopening omits `create`; reopening also omits `host` when the device has its
cached verified binding. Applications do not implement a bootstrap journal.

For explicit lower-level publication, prepare the public configuration fields
from that same executable definition:

```ts
import { prepareNativeSqlApplication, openNativeSqlApplication } from '@chronolog/peer-session/sql-native'

const prepared = await prepareNativeSqlApplication({
  applicationId, definition, schemaAdministrator: device.identity,
})
await host.peers.configureApplication({
  ...prepared, historyId, epoch: 0, keyDigest,
  members: [{ publicKey: device.identity.publicKey }],
})
```

The result contains `definition`, signed `schema`, `executionManifestDigest` and
`schemaAdministrator`. Spread these fields directly into hosted configuration;
the host derives and verifies the descriptor digests. The application identity
must match the peer page being configured. The schema administrator is separate
from the host's control signer and from a device's shared-data role.

For the initial creator, open the SQL session with the verified authority,
executable definition and explicit epoch keys. Normal reopening loads the
persisted keyring and omits `epochKeys`:

```ts
const session = await openNativeSqlApplication({
  device, definition, authority, epochKeys,
  databasePath: './application.sqlite', schema: prepared.schema,
})
```

Opening verifies the signed schema and execution identity against the descriptor
before creating a SQL database, then initializes it before replaying application
commands. The session claims exclusive device ownership before opening the
materializer and closes it before releasing device storage. Ordinary commands
cannot change the schema or protected platform tables. `dataRole` controls
membership in the shared application collective; a null role still permits
authorized personal rows owned by the actual command author.
Shared rows can use `APPLICATION_COLLECTIVE_ID` when the domain allows current
members to edit them. Creator departure does not freeze those rows, and signed
data-role revocation remains effective through history rollback.

## Browser SQL composition

The portable and ordinary browser entries remain SQL-free. The optional
`/sql-browser` entry constructs the same deterministic materializer in an
isolated owning Worker and takes `engineUrl` instead of a database path. Serve
the packaged `browser-engine` directory as static assets with JavaScript/WASM
content types and the same cross-origin isolation policy as the Worker. The
directory URL may include or omit its final slash. For example:

```ts
import { openBrowserSqlSession } from '@chronolog/peer-session/sql-browser'

const session = await openBrowserSqlSession({
  device, definition, applicationId, host, create: {},
  engineUrl: new URL('/chronolog-engine/', self.location.href),
})
```

As in native SQL, omit `create` when joining or reopening and omit `host` for
cached offline reopening. The explicit `openBrowserSqlApplication` constructor
accepts already verified `authority` and `schema` for custom composition.
`prepareBrowserSqlApplication({ applicationId, definition, schemaAdministrator,
engine })` returns the same flat public configuration fields as the native
preparation helper, using the supplied WASM build manifest.

The session verifies the signed initializer, engine bytes and manifest before
creating the database. It opens an OPFS handle pool scoped to the durable storage
identity and application, and releases it when the materializer closes.
`createBrowserSqlManifest(buildManifest)` exposes the matching execution
manifest for bootstrap. Native and browser peers must use that same signed
identity; an incompatible engine fails before initializing the SQL cache.

This composition uses the same page facade and Tendriller adapter described
below. Both SQL databases are derived from authenticated history; they do not
replace original encrypted records, saved operation intent, or the epoch keyring.
External effects retain their dispatch journal across recovery and reconcile
uncertain calls with the provider. Protect prerequisites only when the application
requires them to survive recovery; see
[Shared SQL commands and effects](#shared-sql-commands-and-effects).

## Recovery and inspection

`operations.get(id)` returns saved, applied, abandoned or needsReapply.
`operations.subscribe({ operationId, author?, signal? })` observes one signer's
intent state, including `saved` work before a coordinator is reachable. It
yields the current state when present and coalesces later state changes. The
session permits 16 operation subscriptions, each with one pending value and
one active lookup; cancellation releases a slot after any started lookup ends.
`operations.inspect(id, { author })` includes the retained original signed
attempt, preserving real signer provenance. `operation.retry()` reuses those
bytes. `onRecovery()` and `changes()` report coherent generation transitions.
`changes()` yields the current view first and then coalesces changed views;
retention bookkeeping alone does not emit another applied-view notification.
Explicit recovery notices remain visible, and retention still wakes
`operation.shared()` waiters.
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
next page. The shared storage envelope is at most 4,096 records and 64 MiB of
retained history; replica options may lower either quota. There is no smaller
whole-history network buffer limit. An advertised head is not proof that its
history fits those quotas or has been retained.
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

For an owned network lifecycle, `/webrtc` exports
`maintainApplicationWebRtc(session, { host })` and
`maintainWorkerApplicationWebRtc(session, worker, { host })`. The optional
`/webrtc-native` entry supplies
`maintainNativeApplicationWebRtc(session, { host })`. These helpers own discovery,
coarse advertisements, invitations, bounded reconnect, catch-up and permitted
takeover. The returned owner exposes `ready`, `status`, `onStatus()`, `reconnect()`
after retry exhaustion, and async `close()`; closing it leaves the application
session's lifetime unchanged.

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

SQL read views lease the already verified immutable published reader. Capturing
or querying the current view opens no database connection and creates no branch.
An update installs a new verified reader; the old reader and its process-owned
reference remain alive until its last held view is released. SQL and events
therefore stay at the same captured revision through append and prefix recovery.
This removes storage work caused by repeated reads. It does not compact the
database WAL or prune authenticated history.

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
The adapter's `sql: true` option exposes SQL reads only when the owned native or
browser session has a qualified SQL materializer; it does not create one.

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

## Shared SQL commands and effects

Shared SQL rows can use `APPLICATION_COLLECTIVE_ID` ownership when the domain
permits every currently authorized application member to edit them. Signed
controls define its current data roles, so creator departure does not freeze
shared data and data-role revocation survives history rollback. Private row
ownership remains tied to its actual author.

Effects retain their original dispatch journal and provider retry key across
recovery, because an external call may
outlive an abandoned application record. Before dispatch, check current intent
and authorization; reconcile uncertain calls with the provider. Use the recovery
floor when an application specifically requires an action's prerequisite to survive
recovery. See [integration details](../../docs/plans/peer-generation-integration-details.md).

### A shared SQL command with a domain guard

The signed initializer creates the application tables. The materializer adds
`chronolog_owner`, whose value is an internal principal ID. Use
`OWNER_FOR_KEY_SQL` with a bound `APPLICATION_COLLECTIVE_ID` to create shared
rows; do not put the 32-byte key directly into that integer column. Omitting an
explicit owner creates a row owned by its signing author.

```ts
import {
  APPLICATION_COLLECTIVE_ID, OWNER_FOR_KEY_SQL, defineApplication,
  defineCommand, defineQuery, emit, program, sqlStatement,
} from '@chronolog/peer-session'

const tasks = defineApplication({
  id: 'tasks', version: '1',
  schema: program(`CREATE TABLE tasks (
    id TEXT PRIMARY KEY, title TEXT NOT NULL,
    done INTEGER NOT NULL DEFAULT 0 CHECK (done IN (0, 1))
  )`),
  commands: {
    create: defineCommand({
      description: 'Create a shared task',
      input: { type: 'object', properties: {
        id: { type: 'string', minLength: 1, maxLength: 128 },
        title: { type: 'string', minLength: 1, maxLength: 200 },
      }, required: ['id', 'title'] },
      prepare: ({ id, title }) => program(
        sqlStatement(
          `INSERT INTO tasks (id, title, chronolog_owner)
           VALUES (?, ?, ${OWNER_FOR_KEY_SQL})`,
          [id, title, APPLICATION_COLLECTIVE_ID],
        ),
        emit('task.created', { id, title }),
      ),
    }),
    complete: defineCommand({
      description: 'Complete an open task',
      input: { type: 'string', minLength: 1, maxLength: 128 },
      prepare: id => program(
        sqlStatement(
          `SELECT chronolog_assert(
            EXISTS (SELECT 1 FROM tasks WHERE id = ? AND done = 0),
            'task_not_open')`, [id],
        ),
        sqlStatement('UPDATE tasks SET done = 1 WHERE id = ?', [id]),
        emit('task.completed', { id }),
      ),
    }),
  },
  queries: {
    tasks: defineQuery({
      description: 'Read shared tasks', input: { type: 'null' },
      read: view => view.query('SELECT id, title, done FROM tasks ORDER BY id'),
    }),
  },
})
```

Pass `definition: tasks` to either SQL session opener. `sqlStatement` binds
ordinary numbers, strings, booleans, nulls and byte arrays without interpolation.
`chronolog_assert(condition, code)` rejects the whole command when the condition
is false or null. A rejected command publishes neither its row changes nor its
events. Inspect `operation.applied()` for `outcome` and `rejectionCode`; an
applied rejection is still an ordered outcome. Domain guards run against the
selected history at execution, including when two peers act on the same earlier
view. A command's optional `basedOn` revision also makes its observed view
explicit, but does not replace those domain guards.

For first publication, `create.members` can name the public keys of devices
already created with `openNativeDevice` or `openBrowserDevice`:
`create: { members: [{ publicKey: a.identity.publicKey },
{ publicKey: b.identity.publicKey }] }`. Those ordinary participants can read,
write, coordinate and request recovery. These grants are separate from the
initializer's schema authority and the host's administration rights. Later
enrollment is a signed control change through the host's
public membership API, followed by peer-to-peer key delivery.

## Signed page releases

The optional `/releases` entry shares the owned device's signer and store for
immutable page manifests, resumable publication, and exact activation retries.
Publisher policy and release selection remain independent of application-data
recovery. See [Signed page releases](releases.md) for the public API, explicit
rollback, content verification, and lifetime contract.

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
the native SQL archive into an empty independent project, verifies its recorded
file hashes, and exercises canonical configuration, shared rows, constraint
rejection, generation recovery, creator departure and reopen without workspace
imports or install scripts.
