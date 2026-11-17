# Native application agent service

This package runs a native inclusion and finality service, durable event consumers,
timers, and peer connections alongside an application agent. The loops do not
depend on model turns. Provider calls stay in trusted application modules;
Chronolog's execution and UI replay never call them.

Start with the [application primitives guide](../../docs/application-primitives.md)
for the choice between signals, durable events and SQL, and for the separate
membership, finality and external-effect roles.

## Run the native profile

For a new durable native history:

```sh
CHRONOLOG_DATA_DIR=/persistent/chronolog-agent \
CHRONOLOG_HISTORY_POLICY=coordinated \
CHRONOLOG_EXECUTION_PROFILE=events \
pnpm dev
```

Use `CHRONOLOG_EXECUTION_PROFILE=sql` for a mixed SQL/event group. The `events`
profile dynamically avoids importing the application SQL adapter. A stored
genesis pins the execution profile and history policy; changing either on a
continuing history is an error. `peer` remains a separately selected native
policy. Leaving `CHRONOLOG_HISTORY_POLICY` unset uses an existing genesis, or
creates the ordinary peer profile for a new daemon.

The `coordinated` configuration selects a signed-inclusion provider; it never
changes application ordering. Every replica executes proposals by their signed
author timestamp and the protocol's deterministic tie-breakers. Its genesis
records one history ID and the daemon's persistent signing key as finality
authority. Another enrolled node does not become that authority
unless its key is the one that genesis explicitly names. The daemon uses its
existing fenced data directory and FULL-synchronous SQLite operation store.
`CHRONOLOG_FINALITY_RECORD_QUOTA_BYTES` bounds retained descriptors and closure records;
`CHRONOLOG_FINALITY_PAYLOAD_QUOTA_BYTES` separately bounds detached application
bodies. Each defaults to 64 MiB. Exhaustion is a visible refusal; no record is
silently trimmed. These are service budgets, not a limit on the entire node's
database, which also holds replica state and application checkpoints.

The daemon's ready output includes the selected policy, execution profile,
resident task IDs, and whether it hosts the native finality service. Task failures stop
the resident service and are reported as `chronologd.agent_failed`.

## Finality service storage and recovery

`NativeFinalityService` composes the public
`ReferenceRecordLog`, signed closure markers and prefix certificates. Exact bytes,
deduplication, receipt entries and the rolling head are one atomic record-store
update before append acknowledgment. Receipt positions enumerate inclusion;
replicas independently derive chronological execution order.

Opening the service requires the authenticated enrollment descriptor. It verifies
the descriptor, the pinned signer, the signed-inclusion provider and the signed
clock policy before accepting work. Persist the identity first, sign a genesis
that names its public key and the reserved history ID, then open the service:

```ts
const finality = await NativeFinalityService.open({
  descriptor,
  identity: persistentSigningKey,
  store: durableStore,
  recordQuotaBytes: 64 * 1024 * 1024,
  payloadQuotaBytes: 64 * 1024 * 1024,
})
```

`LiveInclusionFinalityProvider` is the replica's proof-verification port; the service above
produces those proofs. An agent can consume final events without hosting either
the signing key or this service. The default daemon co-locates these roles as an
explicit deployment choice, and exposes the optional service as `context.finality`.

`certify()` uses the provider clock and signed `cutoffLagMs` to close author
time. It signs a marker naming the exact preceding receipt head, commits that
marker, then returns a certificate for the committed prefix. Every earlier
closure stays in retained history, so a fresh peer can reject a proposal first
included after its author timestamp was already closed. Exact retries retain
their original receipt. Prefix certificates remain outside the log they certify.

`serve(transport)` includes retained local records before its first new closure,
then follows durable submissions and advances the frontier on the
signed `heartbeatIntervalMs` timer while admissible proposals still need closure.
`now` is injectable for deterministic fixtures; it never changes the signed policy. Timing has one source: the authenticated
genesis. There are no independently configurable service timing defaults.
Retained exact retries do not trigger extra closures.

The service derives its future-admission window from signed
`maxFutureSkewMs + cutoffLagMs`. A proposal's
author time must be at most its first covering closure plus that window. Replicas
reject a later timestamp deterministically. Without inspecting encrypted bodies,
the service therefore knows when all covered proposals could have become final.
It stops advancing after the greatest such horizon, reconstructs that bound on
reopen, and skips full-history validation on quiet timer ticks once it is reached.
An empty log needs no closure marker. New receipts restart the bounded tail.

Closure markers consume the same explicit retained-history quota as other
records. `certifiedRead()` captures the post-closure range and certificate under
one append lock, and `share()` forwards the selected entries and their covering
certificate. A receiver waits for every retained entry needed to verify the
complete prefix, including its closure markers.

Before storing a detached body, the service durably reserves its exact hash and
length against `payloadQuotaBytes`. Exact retries reuse that reservation, including
after a lost write acknowledgment. A failure between reservation, body storage
and receipt append leaves accounted capacity; it cannot accumulate unbounded
orphan bodies. Reservations are retained because this service has no pruning.
`storageUsage()` reports retained record bytes and reserved body bytes with their
separate limits. Missing reservation state on an established history is a visible
`FINALITY_PAYLOAD_STATE_MISSING` refusal, not an empty replacement budget.

First setup durably creates an empty record log and payload reservation index
before saving the service's configuration. A later open with saved configuration
requires that log; a missing
log fails with `AUTHORITY_CONTINUITY_NOT_ESTABLISHED`. Any retained certificate is
authenticated against the pinned configuration and must match the retained log
at its certified position. Invalid retained proof fails with
`AUTHORITY_RETAINED_CERTIFICATE_INVALID`; a shorter or conflicting prefix fails
the continuity check. Failed opens preserve the surviving state. A log may be
ahead of its last certificate after an interrupted append, and exact retries
keep their original positions.

`NativeAgentStore` supplies the same atomic bytes port for embedded native hosts.
It holds SQLite's exclusive owner fence for the lifetime of the connection and
can back `DurableFeedStore`, authoring state, the finality service, and checkpoints.
The existing daemon instead shares its already fenced node-state database.

A persistent volume is required. A certificate proves inclusion, not a second
durable copy or an external backup. An unavailable service pauses new finality;
peers retain local reads and already certified history. There is no automatic
signer or policy failover.

After restoring a volume, establish continuity independently before continuing
the same signer/history. The `continuity` option to `NativeFinalityService.open` and
`CHRONOLOG_FINALITY_CONTINUITY_FILE` accept a trusted `{historyId, position,
root}` checkpoint and refuse an older or conflicting retained prefix. A
checkpoint copied from the same old backup cannot detect rollback. The automatic
local certificate check detects partial loss or contradiction; it cannot detect
rollback of the entire consistent volume, including that certificate. Without
established continuity, create an explicit new history lineage. Neither this
package nor a missing newer peer certificate proves that a restored backup was
the latest acknowledged state.

The [authority recovery rehearsal](../../docs/authority-recovery.md) executes
real process kills at payload/record/certificate/acknowledgment boundaries,
accepted and rejected exact retries, whole-state backup/restore, same-file
writer fencing, an authority-task outage and explicit refusal of a stale backup
after the current disk is deleted. It emits public evidence separately from
secret-bearing disposable stores and lists the deployed-volume and Cloudflare
recovery checks still required.

## Trusted application modules

Set `CHRONOLOG_AGENT_MODULE` to a local module exporting `createAgent(context)`.
The public `AgentApplicationModule` and `AgentApplicationContext` types are
exported from `@chronolog/agent-service`. A factory describes its workers and
long-lived connection tasks; it should not wait for final publication during
configuration, before the resident loops start.

The module owns its runtime dependencies. The native distribution does not
include the optional `@chronolog/transport-webrtc` package or its Werift
implementation. Setting `CHRONOLOG_AGENT_MODULE` loads the specified file; it
does not install dependencies or expose the daemon's dependencies to that file.
For a resident HTTPS/WebRTC task, build and ship the application module with its
transport dependencies from the matching Chronolog source checkout, following
the [native transport packaging guide](../transport-webrtc/README.md#shipping-a-native-application-module).
Point the environment variable at the absolute path of the resulting module
exporting `createAgent`, which composes the resident task with the rest of the
application. The contrib `serve-resident-webrtc.mjs` snippet exports a task
factory and must be included in that composition.

```ts
import type { AgentApplication } from '@chronolog/agent-service'

export function createAgent(): AgentApplication {
  return {
    effects: [{
      resultTopic: 'job-results',
      handler: {
        id: 'job-provider',
        version: '1',
        topics: ['job-requests'],
        recovery: 'idempotent',
        async dispatch({ event, idempotencyKey, signal }) {
          return provider.perform(event.payload, { idempotencyKey, signal })
        },
      },
    }],
  }
}
```

`provider` in this sketch is an application-owned integration. The runnable
`examples/resident-agent.ts` module reads shared final task rows and formats a
bounded `job.completed`/`job.failed` result without an external provider. It is
the handler used by the contrib task-board vocabulary. The worker publishes
`effect.completed` on `job-results`, with the returned value in `result` and the
stable request event in `originEventId`. Browser grants allow `job-requests`;
only the designated native worker receives `job-results` publication rights.

The context supplies the public node, atomic private store, final event
publisher, optional finality service, live `context.signals`, and authenticated
peer connection setup. The module is trusted native code. Keep credentials,
private model context, and private workflow state in its local store or another
explicitly authorized group; topic filtering is not confidentiality.

## Final-intent processing

`DurableEffectWorker` uses a distinct durable event source, never a coalescing
snapshot subscription. It keeps the pending bounded batch, dispatch state, and
processed cursor together. Individual programs and the source batch are bounded;
slow workers resume from storage.

For each event it:

1. Derives a stable effect ID from source/history, event ID, handler ID, and version.
2. Commits dispatch intent before calling the provider.
3. Commits the provider result before publishing a result event.
4. Retries result publication with the same operation ID and bytes.
5. Advances durable processing only after final accepted result publication.

The provider's recovery policy is explicit:

| Mode | Recovery after a possible provider call |
| --- | --- |
| `idempotent` | Call again with the same provider idempotency key. The provider must guarantee deduplication. |
| `reconcile` | Ask the provider whether the call completed, did not happen, or remains uncertain. |
| `manual` | Leave the effect in `dispatching` and raise `EFFECT_OUTCOME_UNCERTAIN`. |

`resolve(effectId, result)` records an explicit recovered completion or a verified
`not-performed` decision. A local retry key does not manufacture exactly-once
external effects. Result payloads and their metadata must fit the bounded event
contract; store large provider outputs as explicit blob references.

Handlers receive `signal` and `deadlineAtMs`; pass cancellation through to the
provider SDK. Each dispatch or reconciliation has a bounded `timeoutMs` (60
seconds by default, at most five minutes). Shutdown cancels the call and stops
waiting even when an asynchronous provider ignores cancellation. Its checkpoint
remains `dispatching`; a late completion is not published by the stopped worker.
Timeout or cancellation does not prove that the external action was prevented,
so the same explicit recovery policy still applies on restart.

One designated worker owns each handler. A changed handler version, topic filter,
or source cannot silently reuse its checkpoint. Pure UI caches may rebuild;
discarding an external-effect checkpoint can repeat actions and requires an
intentional application recovery decision.

`CheckpointStore` also exposes a small general state/cursor pair for pure local
projections. Its binding identifies group/history, filter/version, and reducer
version. One `commit` atomically replaces state, revision, and processed cursor.

## Timers and cancellation

`DurableTimerScheduler` consumes final configuration events with explicit,
preallocated schedule generations:

```ts
{ type: 'timer.scheduled', version: 1, timerId, generation, dueAtMs, intervalMs, payload }
{ type: 'timer.cancelled', version: 1, timerId, generation }
```

Allocate the generation before the signed SQL + event program. The resulting
content-derived event ID cannot be inserted into that same program without a
hash cycle. The scheduler separately preserves `configurationEventId` as audit
provenance. Occurrences bind source/history, timer, generation, and scheduled time;
their ID and observed time are durable before publication and survive retries.
An older cancellation cannot cancel a replacement generation. Recurrence uses
scheduled time, not dispatch time, so bounded catch-up does not drift the schedule.

Mixed SQL/event deployments use the concrete `createSqlTimerPublisher` export:

```ts
const publisher = createSqlTimerPublisher({
  node: context.node,
  configurationTopic: 'timers.configuration',
  occurrenceTopic: 'timers.fired',
});

// Run after the resident authority/replication loops have started. Persist these
// operation IDs with the reviewed requests; do not mint new IDs on retry.
await publisher.initialize({ operationId: 'timer-schema-1', signal });
const proposalId = await publisher.schedule({
  timerId: 'review-reminder', generation, dueAtMs, payload: { taskId },
}, { operationId, expectedGeneration: null, signal });
// Replacement supplies the exact prior generation, and a fresh generation above.
await publisher.cancel({ timerId: 'review-reminder', generation }, {
  operationId: cancelOperationId, signal,
});
```

These methods return the original proposal ID only after final acceptance and
throw `SqlTimerRejectedError` for final rejection. They use ordinary public
`node.publish`, `node.operation`, and `node.revisions`; no private authority
hooks or local acceptance shortcut is used. Schema initialization is an explicit
one-time application program under a stable operation ID. The default tables are
`agent_timer_heads`, `agent_timer_generations`, and `agent_timer_occurrences`;
`tablePrefix` can name an isolated application namespace. The permanent generation
ledger prevents a new schedule from reusing an old generation and reviving stale
pending work. No backward schema migration is supplied for this prerelease API.

The occurrence publisher validates the active generation, exact next due time,
and canonical payload with SQL assertions. It inserts the occurrence, advances
or retires the schedule, and emits `timer.fired` in one program. A cancellation
ordered first causes final `cancelled` without an effective occurrence event.
An accepted exact retry keeps its earlier result after a later cancellation.
Only the defined inactive-generation assertion maps to `cancelled`; SQL failures,
permission refusals, time overflow, and unrelated rejections remain visible
errors. Clock observation alone never supplies canonical fencing.

Supply this publisher to a module's `timers` entry or a directly opened
`DurableTimerScheduler`. The scheduler passes shutdown cancellation into finality
waits and retains an unfinished occurrence for exact retry. Do not await final
publication from `createAgent` before the daemon starts its resident loops.
Event-only groups can use the smaller `TimerOccurrencePublisher` port with their
own defined atomic acceptance model; they cannot use the SQL implementation.

Timers emit final intent, and an effect worker performs any outside action.
Cancellation prevents an occurrence that has not already won canonical
admission. A previously final intent and an in-flight external action need the
provider's explicit cancellation/reconciliation policy; the log does not make
an external call atomic with a later cancellation.

## Authenticated peer connections

The default browser/native composition uses independent reliable and live data
channels from [`@chronolog/transport-webrtc`](../transport-webrtc/README.md). The
page negotiates one connection and synchronously transfers both untouched
channels to the exclusive replica Worker. The Worker frames them, awaits the
bounded reliable handshake, then authenticates the Chronolog peer and attaches
replication. Signals use the separate unordered datagram lane after the same
authentication; a large body or exhausted history credit cannot queue a signal
behind durable replication. A reliable-only stream has no implicit signal path.
A reachable resident accepts one direct HTTPS offer/answer; optional Tendriller
rendezvous requires both endpoints to join the same attempt. Neither introduction
path carries application frames or supplies an automatic hosted data fallback.

`framePeerStream` adapts a reliable `ReadableStream`/`WritableStream` pair to
bounded length-prefixed frames, backpressure, cancellation, and truncated-frame
errors when a deployment explicitly selects a generic stream transport. Supply
appropriate transport security, such as WSS/QUIC; length framing does not provide
encryption or NAT traversal.

`openAuthenticatedPeerLink` adds a mutual nonce/signature handshake bound to
group identity and each participant's active read grant. It creates an ordinary
`FeedLink` for the existing retained feed/evidence pull protocol. It never trusts
rendezvous hints or a host login as database membership. Each record or payload
release rechecks the receiver's known active grant, including after asynchronous
storage reads or previous writes. A connection can carry records by other
original authors; endpoint and record identities remain distinct.

`readPayload(hash)` requests one detached application envelope by its SHA-256
address. Header/evidence synchronization does not request these bodies. The
provider and receiver both check the address and the 1 MiB envelope bound, and
the provider rechecks read authorization after its storage lookup completes.
Missing data returns `null`; it does not advance application progress. The
normal ledger decoder additionally checks the envelope against the committed
descriptor's kind, route, epoch and length before execution. These requests
share the session's existing concurrency, timeout and backpressure bounds;
they do not append another record or create a separate payload history.

The native `FeedTransport` exports `asLink()`, `connectLink()`,
`disconnectLink()`, and `catchUpLinks()`. Its native SSB adapter and framed
connections share the same signed record store. The portable browser transport
uses `asLink()` and `connect()`. The daemon module context exposes `signals` on every governed replica and
`finality` only when it owns the signed native provider.
`connectPeer({ connection, peerIdentity? })` performs active reader authorization,
attaches replication and the connection's optional live signal lane, and returns a session with an
`AbortSignal`, `completion` and `close()`. No writer grant or callback injection is
needed to receive signals. Sending selects the currently active writer credential
for that topic at the time of publication. `connect()` and `connectLink()` return a detach function bound to that
connection. Session owners use it on completion or close: delayed cleanup from an
old route cannot remove a replacement connection for the same identity. The
explicit `disconnect(identity)` / `disconnectLink(identity)` methods deliberately
remove whichever connection currently owns that identity.

Peer frames use canonical CBOR with domain `chronolog/peer/v1`; ephemeral frames
use `chronolog/signal/v1`. The reliable lane multiplexes bounded range responses,
content-addressed payload responses and change hints. Best-effort signals use
the separately bounded `connection.live` lane after the same peer authentication;
a reliable-only connection provides replication without advertising a signal route.
Signals cannot hold up retained range handling. At most eight signal callbacks run per
connection; exceeding this bound fails the session before application acceptance. There are at most four pending requests in either direction and each
range is bounded to 64 records / 64 MiB. The event program limit normally makes
actual batches considerably smaller. Connections require deployment measurement
before making direct-connect, relay-bandwidth, or cost claims.

`openAuthenticatedPeerLink` separates four deadline options:

| Option | Default | Bound being enforced |
| --- | --- | --- |
| `handshakeTimeoutMs` | 10 seconds | Absolute identity-proof deadline, including a blocked initial send. |
| `sendTimeoutMs` | 30 seconds | Local request dispatch through the framed connection. |
| `responseIdleTimeoutMs` | 30 seconds | Silence after dispatch or the last validated record for that request. |
| `requestTimeoutMs` | 120 seconds | Absolute request lifetime, including dispatch and every response. |

Values are positive integer milliseconds. Authentication permits at most
60 seconds; each other option permits at most 120 seconds. The dispatch and
idle defaults allow the RTC adapter's ordinary 30-second frame-send budget.
These limits apply to feed ranges, evidence ranges and detached payload reads.

Validated record progress restarts only that request's idle deadline. Change
hints, ephemeral signals and another request's responses do not extend it, and
no progress extends the original hard lifetime. Responses may arrive before the
local send promise settles; a late send completion cannot restart their idle
deadline or revive a completed request. Silence, blocked dispatch or lifetime
expiry fails the session and rejects its pending requests. Completion, remote
errors, cancellation and session failure clear every request timer. Reconnection
resumes from retained verified history with the original operation identities.

## Live signals

Native application modules use `context.signals.send(topic, payload, { ttlMs })`
and `context.signals.subscribe({ topics, mode, signal })`. The public
`ChronologClient.signals` uses the same interface through native or Worker RPC.
`context.connectPeer()` automatically attaches signal routes and the resident
forwards verified original frames to its other current readers. Application code
no longer constructs a separate channel or hand-wires forwarding. Connection
completion and shutdown detach the exact route that owns the session.

The default `mode: 'all'` preserves accepted messages in a bounded FIFO and raises
`SIGNAL_SUBSCRIPTION_OVERFLOW` when a subscriber falls behind. Choose
`mode: 'latest'` for replaceable presence/cursor values per author, session and
topic. Messages expire, have no catch-up history, and never advance a durable
cursor or trigger a finality wait. TTL begins at the original `send()` call,
including queued work. No route means immediate `SIGNAL_DISCONNECTED`; the client
never retries sends or reconnects subscriptions behind the application's back.

The group adapter checks independent current `program.signals` rights; a
signal-only grant may set `sql: false` and `topics: []`. Reading alone does not
allow sending. A reader needs no writer grant to subscribe. Peer links recheck
recipient reader access before signal release, including after asynchronous
work. An offline peer cannot know a revocation it has not received.

The standalone [`@chronolog/signals`](../signals/README.md) package provides
`SignalChannel` for applications without a database. Its caller supplies scope,
identity, byte transport and an explicit authorization callback. Credentials are
optional and opaque; there is no SQL, membership, log, finality or authority
prerequisite. The group integration is one policy adapter over that core.

## Signed membership ledger endpoint

`createMembershipLedgerHandler({ finality, descriptor, sink? })`, exported from
`@chronolog/agent-service/membership-http`, serves exact `POST /_chronolog/membership`
requests as raw canonical CBOR. Each request is signed by the genesis roster root
and binds the group, exact history configuration, request, nonce and short expiry.
The native authority key remains separate. The daemon mounts this handler only
when it hosts the group's pinned native authority. The ordinary owner RPC bearer
does not authorize this route; its independently verified signature does.

Reads return consecutive finalized controls, the signed cumulative projection
checkpoint, and its covering prefix certificate. They return no application
descriptors or bodies. The `after` cursor counts controls; the authenticated
application receipt frontier is separate. Appends accept only inline capability
or epoch records. The native log commits before acknowledgment, so a lost
response returns the same original position on exact retry.

When a sink is configured, the handler repairs complete receipt evidence to
that local native sink. Those entries do not enter the membership HTTP response.
Read pages carry at most 1 MiB of encoded controls and 128 entries; responses and
requests are capped at 2 MiB. Key-wrap lists remain subject to the explicit
inline control limit. See [compact membership proofs](../../docs/membership-control-proofs.md)
for signature, completeness, activation, and bounded synchronization rules.

## Verification scope

Focused tests cover native fencing/reopen, lost append responses, visible quotas,
continuity refusal, peer evidence relay, worker crash ambiguity and reconciliation,
checkpoint atomicity, timer generations and lost responses, signed signal replay,
framing/backpressure, and native/portable framed range exchange. The daemon
composition test runs the actual governed event-only core, authority and worker.
The framed native test uses no SSB listener/NAT and stubs only optional host
interface discovery. These tests do not qualify home/mobile/corporate networks,
browser suspension, provider-specific idempotency, or production relay byte
routes; those need deployment-specific evidence.
