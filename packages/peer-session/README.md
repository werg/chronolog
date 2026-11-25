# `@chronolog/peer-session`

A local-first signed operation-set runtime for native applications and browser Workers. Devices retain immutable authored intents, union verified facts, and independently replay eligible operations. Application order is only `(signed authorTimestampMs: bigint, author public-key bytes, canonical proposal-ID bytes)`. Arrival, transport counters, host clocks and participant placement do not assign order.

The [authored operation-set contract](../../docs/CRDT_CONTRACT.md) is normative. This is a new format, not a reader or migration for the removed protocol.

## Public entrypoints

| Import | Purpose |
| --- | --- |
| `@chronolog/peer-session` | `createApplicationSession`, definitions, authority helpers/types, live views, view stores, projections, scoped tools, single/multi-session event forwarding, checkpoints and owner composition |
| `@chronolog/peer-session/native` | `openNativeDevice` (optional `managedSigner`), `openDisposableNativeDevice`, `NativeBytesStore`, `createApplicationSession` |
| `@chronolog/peer-session/worker` | `openBrowserDevice`, `createApplicationSession`, `createApplicationOwner`, owner locks and lazy browser capability probing |
| `@chronolog/peer-session/browser` | `connectApplicationOwner`, the page facade, live views, view stores, scoped tools and event forwarding; no signing keys or SQL engine |
| `@chronolog/peer-session/webrtc` | Browser RTC transport and the page/Worker raw-frame bridge |
| `@chronolog/peer-session/webrtc-native` | Native RTC transport |
| `@chronolog/peer-session/websocket` | Separate reliable/live WebSocket transport lanes |
| `@chronolog/peer-session/tendriller` | `createApplicationBackend` for the host runtime |
| `@chronolog/peer-session/sql` | `createSqlMaterializationRuntime({ engine, path, rootPrincipal, ... })` in SQL-enabled archives |
| `@chronolog/peer-session/sql-native` | `createNativeSqlEngine` |
| `@chronolog/peer-session/sql-browser` | Verified browser WASM loader, `createBrowserSqlEngine`, `createDoltLiteExecutionManifest`, `digestEngineManifest` |
| `@chronolog/peer-session/sql-wasm` | Node WASM loader and engine capability |
| `@chronolog/peer-session/celld` | Object-owned device/byte storage and managed signer import |
| `@chronolog/peer-session/sql-celld` | `createCelldSqlEngine` and the common SQL runtime factory |

Importing a passive entry does not open a database. Calling `createApplicationSession` explicitly opens local owned storage and cached authority; materialization then warms independently of submission. SQL engine selection remains explicit. Browser/page entries do not eagerly load native SQL or native RTC.

## Define preparation and coherent reads

```ts
import {
  defineApplication, defineCommand, defineQuery, emit, program,
  type ApplicationReadView,
} from '@chronolog/peer-session'

export const notes = defineApplication({
  id: 'notes',
  version: '1',
  commands: {
    add: defineCommand({
      description: 'Add a note',
      input: { type: 'string', minLength: 1, maxLength: 4096 },
      prepare: text => program(emit('note', { text })),
    }),
  },
  queries: {
    notes: defineQuery({
      description: 'Read effective note events',
      input: { type: 'null' },
      read: (view: ApplicationReadView) => view.readEvents({ topics: ['note'] }),
    }),
  },
})
```

Definition versions describe an API; they are not admission locks or database schema hashes. A named `session.query(name, input)` returns `{ applicationId, revision, value }`. A captured `view.query(sql, parameters)` returns rows directly, with its revision on the view.

## Explicit enrollment, then local reopening

First setup creates a device only when explicitly requested. The owner signs in and completes enrollment/key provisioning. For a fresh browser-first application, `rootPrincipal` is the actual first owning browser key, not an invented native identity. Signing identities, epoch keys and private setup state stay in the owning Worker or native profile, never in published assets.

```ts
import { createApplicationSession } from '@chronolog/peer-session'
import { openNativeDevice } from '@chronolog/peer-session/native'

// Explicit first device creation; omit create when reopening an existing profile.
const device = await openNativeDevice({ path: './private/device.sqlite', create: true })

// verifiedAuthority and initialEpochKeys come from trusted enrollment/provisioning.
const session = await createApplicationSession({
  device,
  definition: notes,
  authority: verifiedAuthority,
  epochKeys: initialEpochKeys,
})
```

Subsequent activations can call `createApplicationSession({ device, definition: notes, applicationId })` using cached authority and keys, before host lookup. Missing identity/storage fails explicitly; it does not mint a replacement signer.

Authority metadata and encryption grants are separate from application SQL permissions. An unchanged writer grant remains usable by an offline cached certificate. A writer revocation interrupts that certificate; a later regrant does not silently revive it. Original operations remain stored for inspection even when excluded from replay.

For browser ownership:

```ts
// Inside the owning Worker. Fresh setup has already verified/provisioned this profile.
import {
  openBrowserDevice, createApplicationSession, createApplicationOwner,
} from '@chronolog/peer-session/worker'

const device = await openBrowserDevice({ name: 'notes-profile' })
const session = await createApplicationSession({ device, definition: notes, applicationId })
const owner = createApplicationOwner(session)
owner.attach(self)

// In the page; no private key or store crosses this port.
import { connectApplicationOwner } from '@chronolog/peer-session/browser'
const client = await connectApplicationOwner(worker, { applicationId })
```

Acquire `acquireApplicationOwnerLock(profileId)` before opening a shared browser profile. Reuse the same owned device records on resume. Multiple authenticated attachments can share one owner; they do not create independent signers or stores.

## Durable submission and independent facts

```ts
const operation = await session.command('add', 'Hello', {
  operationId: crypto.randomUUID(), // retain this handle for uncertain replies
})
// Return means the exact signed intent is durable locally, not that SQL/network/finality completed.
const local = await operation.materialized()
const inspection = operation.inspect() // async on the page facade
```

- `stored`: exact signed intent is retained on this device.
- `materialized()`: accepted/rejected local outcome at an operation-set revision. Earlier late operations can revise it.
- `retained()`: authenticated availability assertions from other signing identities and other storage IDs. Each binds the original author and the canonical digest of an exact stored signed envelope, not just a claimed proposal ID. Keyless encrypted storage can acknowledge that physical subject without waiting for SQL. Only matching known subjects from currently trusted peers qualify; raw historical/unknown-subject evidence remains retained for verification/gossip. Local/self-echo evidence does not qualify. It does not prove execution, finality or permanent availability.
- `finalized()`: inclusion/closed-time evidence under the configured policy, with necessary local dependencies and replay complete. `none` explicitly returns `FINALITY_UNSUPPORTED`.

Default author timestamps are allocated once from wall time and this owner's durable default allocations. Explicit local or remote future timestamps do not advance that allocator. Provided timestamps are never clamped or rewritten. Exact retries preserve the original core, timestamp, nonce, signature and envelope; changed input under a reused handle is rejected.

Use `session.operations.get(ownedOperationIdOrProposalId)`, `operations.subscribe({ operationId, signal })`, and `operations.retry(id)`. Retry wakes the original stored intent and replication/dependency work; it does not reprepare or retimestamp it. A bounded same-owner preparation cache also preserves signatures after a precommit storage error. If nothing ever became durable and that owner process crashes, the intent remains unsaved; retain and review the original UI input rather than claiming restart preservation.

## Ordinary SQL, DDL and permissions

```ts
import { createSqlMaterializationRuntime } from '@chronolog/peer-session/sql'
import { createNativeSqlEngine } from '@chronolog/peer-session/sql-native'

const sqlSession = await createApplicationSession({
  device, definition: notes, authority: verifiedSqlAuthority,
  createMaterializer: ({ rootPrincipal }) => createSqlMaterializationRuntime({
    engine: createNativeSqlEngine(), path: './private/application.db', rootPrincipal,
  }),
})

const ddl = await sqlSession.submit({
  operationId: 'reviewed-notes-table',
  program: program('CREATE TABLE notes (id INTEGER PRIMARY KEY, text TEXT)'),
})
const outcome = await ddl.materialized() // may be rejected if this signer lacks namespace rights
```

The descriptor pins engine/platform execution semantics, not an application schema. Only the trusted initial internal permission bootstrap uses `rootPrincipal`. Application DDL, DML, ownership, membership and permission changes are ordinary signed programs with author-time replay and atomic rollback. The creator owns newly created objects; crypto administrators are not implicitly SQL/schema administrators.

Use `platformOp.grantDdl`/`revokeDdl` for namespace/object rights and ordinary platform operations for application grants. `GROUP_COLLECTIVE_ID` names the initial application collective. Host account/device membership does not overwrite that SQL collective.

Keep identity/key records in storage outside the authored SQL image. Native SQL and private records use separate files; Celld deployments must likewise keep private records in private KV or a separate storage facet, not an application-queryable SQL namespace. The `celld` entry can reopen object-owned devices with `openCelldDevice`; SQL still uses the same explicit materializer capability and ordinary programs.

## Reactive snapshots and drafts

```ts
const view = await session.readView()
try {
  const rows = await view.query('SELECT id, text FROM notes ORDER BY id')
  // Render this captured revision; release does not change the signed operation set.
} finally { await view.release() }

const live = createLiveView(session, async view => (await view.readEvents()).events)
await live.ready()
const stop = live.subscribe(snapshot => render(snapshot.value))
```

`createLiveView` invalidates and rederives coherent snapshots after late state/schema/outcome changes. It exposes stale-query failures instead of fabricating rows. `defineProjection`/`createProjection` wrap the same reactive derivation. Keep drafts/focus independent of read snapshots, and close views/subscriptions when their owner ends.

`createViewStore({ storage, applicationId, profileId, viewId })` keeps local drafts and authenticated full proposal references separately from materialized data. Retained references preserve original submission context and reject conflicting replacements. Draft storage is not application authorization or a second application database. Event cursors are scoped to one captured revision/filter; a changed revision requires a fresh read.

## Optional finality and provisioning

`none` is complete local-first operation without a finalizer. Signed-frontier and fixed-validator policies authenticate first inclusion, complete historical admission scopes and closed author-time frontiers; they never provide a comparator or assign operation positions.

- `session.finality.closeAuthorTime({ throughMs })` issues an owned signed-frontier closure, or a one-validator fixed-policy closure.
- `voteAuthorTime({ throughMs })` and `submitProofs(proofs)` support configured fixed-validator quorum evidence. Thresholds are never silently reduced.
- The signer must have an explicit finalizer grant and match the configured policy. Historical evidence survives valid later revocation; an old head cannot bypass revocation for a later author-time range.
- Missing bodies, keys or authority predecessors remain pending. A blocker at T limits closure to T−1. Work first included behind a sealed frontier is explicitly excluded without changing its signed timestamp.

The owning native session and page facade expose:

```ts
const request = await recipient.provisioning.createProvisioningRequest()
const encrypted = await source.provisioning.exportProvisioning(request)
await recipient.provisioning.importProvisioning(encrypted)
```

A public signed request can precede enrollment. Export requires the enrolled recipient's reader grant; import verifies recipient/request/sender scope and signed epoch-key commitments. The recipient's agreement secret remains in its original private owner store. `mergeAuthority(bundle)` verifies and durably retains newer signed membership evidence without adding SQL permissions.

## Content, signals, tools and exporter effects

- `content.putBytes`, `readBytes(ref, { maxBytes })`, `stage`, `read`, `retain`, `retention`, `retained`, and `discard(ref)` use verified encrypted 64 KiB chunks. An explicit upload has `write`, `progress`, `commit`, and `discard`; native/Worker-owner content can `resumeUpload(id)`. Peer pulls resume cached chunks after interruption/restart. Local eviction does not erase authored references or other devices' copies.
- `signals.send(topic, payload, options)` and `signals.subscribe(options)` share disposable signed updates over the independent live lane. `mode: 'latest'` coalesces; `includeLatest` requests still-fresh remembered values. Signal updates never change the application revision.
- `createScopedApplicationTools(session, { commands, queries })` defaults to no named permissions. `operationId(raw, { caller })` and `execute` use the same caller-scoped identity, including an explicit trusted physical binding namespace when present. Inspect/retry/wait cannot adopt another caller's handle.
- `forwardSessionEvents` rederives effective captured snapshots, emits stable-ID upserts/retractions and independent fact updates, and checkpoints a bounded pending delivery ledger before callbacks. Lost acknowledgements can redeliver the same identity. Delivery must be idempotent; neither finality nor this helper promises exactly-once external effects.

## Many applications in one agent process

One agent program can hold one owned device file per application while sharing one retained
`SigningIdentity`. Supply that identity as `managedSigner`; each device file records only its
public key and storage binding, and every resume must supply the same private signer. Shared
identity does not grant application access: authenticate/enroll that key and provision the
explicit reader/writer permissions and epoch keys separately for each application. Publication,
finalizer eligibility and SQL privileges remain independent grants.

```ts
import { createApplicationSession, mergeSessionChanges, forwardManySessionEvents } from '@chronolog/peer-session'
import { openNativeDevice } from '@chronolog/peer-session/native'

// agentSigner is retained in private agent secret storage, never in application assets.
const device = await openNativeDevice({
  path: `./private/apps/${applicationId}.sqlite`, create: true, managedSigner: agentSigner,
})
const session = await createApplicationSession({ device, definition, authority: verifiedAuthority })
// Complete this application's explicit key provisioning before authoring encrypted work.

const changes = mergeSessionChanges([session]) // also accepts an async session registry
changes.add(otherSession)
for await (const { applicationId, kind, revision, revisedProposalIds } of changes) {
  invalidate(applicationId, { kind, revision, revisedProposalIds })
}

const forwarders = forwardManySessionEvents({
  sessions: [session, otherSession], topics: ['note'],
  checkpoints: {
    load: scope => privateLedgers.get(scope.key),
    save: (scope, state) => { privateLedgers.set(scope.key, state) },
  },
  project: (event, _batch, { view }) => ({
    applicationId: view.applicationId, name: event.topic, payload: event.payload,
  }),
  deliver: (projection, event, batch, signal) => deliverForApplication(projection.applicationId, projection, event, batch, signal),
  onError: (error, failed) => report(failed.applicationId, error),
})
```

`mergeSessionChanges` holds at most one pending invalidation per session, supports `add`/`remove`,
and drops a closed or failed source. `onError` isolates a failed source; without it the merged
stream fails. Notifications are cues to reread that application's coherent snapshot, never a
combined application log or cross-application ordering mechanism. Call `changes.close()` when
its consumer ends.

`forwardManySessionEvents` preserves the single-session snapshot/upsert/retract and independent
fact semantics. Its private checkpoint adapter receives `{ applicationId, key }`, with
`key = sessionCheckpointKey(applicationId)`. Run one owned forwarder per application in a
checkpoint namespace; isolate different owner profiles/exporters in separate private adapters.
These are durable pending-delivery ledgers, not arrival cursors or a second application database.
A failed forwarder is reported to `onError` without stopping other applications; `close()` stops
and waits for the group's forwarders. External delivery still requires idempotency. Host traffic
remains approved control/tool/event delivery, not a newly hosted application data backend.

Native record files share one process-wide SQLite pool worker while retaining separate quotas
and exclusive file locks. `NativeBytesStore.poolStatus()` exposes its serving thread and store
count. Closing the last store retires that worker; disposable SQL device directories share one
process-exit cleanup listener. SQL engine and transport resources remain explicit rather than
being implied by the record-store pool.

## Attachment boundaries and lifetime

Owner attachment capabilities independently name `commands`, `queries`, `events`, `content`, `signals`, `operations`, `diagnostics`, `finality`, `provisioning`, and `replication`. Diagnostic access only reads public authority/endpoint metadata; it does not grant private finalizer or key-provisioning actions. `replication` exposes `exportFacts()`/`mergeFacts()` so an attached page can relay the owner's signed, encrypted operation-set facts through an out-of-band replica; merged envelopes are verified against current authority and ordered only by signed author time. Configured command/query allowlists and captured raw-SQL/event checks remain independent. `prepareCommand` receives the actual owner-bound endpoint context, not an unverified document label.

The owner reserves each live attachment's local `viewId`. A cloned tab requesting an already-held ID receives a fresh owner-issued ID; hidden/suspended attachments retain their reservations. Detach or physical close releases the claim so the original page can request its retained ID again. This fences local draft namespaces, not application authorization or operation identity.

The page facade exposes `endpoint`, `boundedRequest`, `detach`, `suspendAttachment`/`suspend`, and `resumeAttachment`. Requests, views, streams and upload handles are bounded; cancellation and physical port loss release owned work, including late acquisitions. Cleanup/detach remain available under a full ordinary request quota. Closing a facade detaches that client; owner shutdown is explicit.

`connectPeer({ connection, peerIdentity? })` authenticates the peer and unions signed facts over bounded encrypted framing. RTC and WebSocket adapters retain separate reliable/live lanes. Signaling/host availability does not gate local Save. A synchronization acknowledgement is not a materialization or finality result.

`session.diagnostics()` (also on the page facade through `diagnostics.peers`) only snapshots existing authenticated links. It returns `{ connectionId, peerId, kind: 'unknown', sentReliableBytes, receivedReliableBytes }`. An instrumented live route additionally reports actual `sentLiveBytes`, `receivedLiveBytes` and detached `signalRejections: { total, clockSkew, expired, unauthorized, duplicate, capacity }`; absent live instrumentation omits these fields instead of inventing zero counters. Counts saturate at safe-integer bounds. Byte counters describe reliable protocol framing or signed live protocol frames, excluding channel-encryption and transport overhead, not NIC totals. Authenticated future/expired signal drops remain nonfatal and do not change the connection revision or application history. No host fetch or new connection is performed. `status.connectionRevision` is a local physical add/remove invalidation counter, never an application position.

The owning Worker/native process must remain running for live participation or assistant event delivery. Page residency and MCP do not establish future wake of an existing conversation. Inspect and report actual process/resume state; do not present installation or a preview as a connected application.

## Private checkpoints and release qualification

Quiesce the owning session before `exportDeviceCheckpoint` or the streaming checkpoint APIs. Persist authenticated encrypted output before source retirement; restore only into a fresh private store, including consistent separately captured SQL bytes. Resume original identity/storage rather than merging SQL state or replacing a missing signer. A backup is not permission to run cloned signing identities concurrently.

Release packaging and source tests are separate gates:

```sh
pnpm lint && pnpm typecheck && pnpm test:fast
pnpm test && pnpm build && pnpm docs:check
node tools/package-peer-session.mjs --sql-native --sql-browser --sql-wasm --sql-celld
```

The default suite reports optional actual-Celld bridge skips unless `CHRONOLOG_CELLD_BINARY` names the rebuilt engine. Browser/native RTC diagnostics run separately. Dirty-source diagnostics are not clean release attestations; deployment is a separate action.

See [release hardening](../../docs/release-hardening.md) and [browser storage](../../docs/browser-storage.md) for qualification boundaries.

### Separate the session owner, request worker and conversation host

A connected session establishes peer transport and authorized application access.
It does not establish that an assistant is processing requests. One native owner
can keep several pages connected while a separate worker is stopped, or while a
one-shot event waiter has already returned. A forwarder can successfully deliver
a notice while the destination conversation remains idle.

Bind live availability to the actual request handler's lifetime and advertised
topics. Workers sharing one signer need distinct consumer/run identities; the
signer alone cannot distinguish a mailbox fetcher from an assistant. Publish
short-lived [signals](../signals/README.md#worker-presence) only while that worker
can accept the named work. Stop its observer, timer and availability announcement
when it exits. A best-effort stopped signal helps graceful shutdown; expiry must
also handle a crash. Do not renew an assistant heartbeat from the session owner's
transport loop, and do not append periodic durable events merely to keep a badge
green. Durable receipt and answer commands remain separate evidence.

A supervised event consumer supplies a durable checkpoint scoped by application,
consumer, filter and captured revision, with one writer per checkpoint. A stored
snapshot cursor does not remain valid after the projection is revised: handle the
explicit reset/stale-cursor boundary and rederive the current effective view.
Preserve stable authenticated event/request identities for deduplication and save
progress only after the required work has a durable outcome. A notice accepted by
a conversation host cannot advance the independent request-handler checkpoint.
Reconnect and inspect retained work before waiting for another disposable signal;
provisional events do not grant irreversible or exactly-once external effects.

Chronolog exposes observation and forwarding, not a model execution loop.
An external host adapter must establish how it submits work to the exact
conversation, injects input into its active turn or starts/resumes an idle turn,
serializes dispatch and reports blocked delivery. For Codex, a plain CLI queue
waits while a turn is running. A receiver that must inject incoming requests
uses the verified `turn/steer` route with the observed active turn identity;
queue/resume is the idle/unloaded route. Steering makes input available at the
next applicable continuation boundary, not an interruption of an in-flight tool.
Preserve explicit user interruption and uncertain admission outcomes. See Tendriller's maintained
[conversation-delivery qualification](https://github.com/werg/tendriller/blob/master/docs/CONVERSATION_DELIVERY.md)
and [worker-owned request example](https://github.com/werg/tendriller/blob/master/docs/AGENT_REQUESTS.md).
A CLI queue or app-server API must be qualified against the installed host and
same conversation; no Chronolog method implies that every Codex or ChatGPT
surface supports it. Verify a request reaches the same active Codex turn before
it ends, then verify idle wake and a second request after the answering turn ends.
A notice queued until completion does not pass the active-delivery check. Stop
only the worker while leaving the native session connected to verify that its
availability disappears and unanswered requests remain retained.
