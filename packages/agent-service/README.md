# Native application agent service

This package runs the fixed coordinating authority, durable event consumers,
timers, and peer connections alongside an application agent. The loops do not
depend on model turns. Provider calls stay in trusted application modules;
Chronolog's execution and UI replay never call them.

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

The coordinated genesis records one history ID and the daemon's persistent
signing key as authority. Another enrolled node does not become an authority
unless its key is the one that genesis explicitly names. The daemon uses its
existing fenced data directory and FULL-synchronous SQLite operation store.
`CHRONOLOG_AUTHORITY_QUOTA_BYTES` bounds retained proposal bytes (64 MiB by
default). Exhaustion is a visible refusal; no record is silently trimmed.

The daemon's ready output includes the selected policy, execution profile,
resident task IDs, and whether it hosts the native authority. Task failures stop
the resident service and are reported as `chronologd.agent_failed`.

## Authority storage and recovery

`NativeAuthority` composes the public `ReferenceRecordLog` and prefix certificate
implementation. Exact bytes, deduplication, ordered entries, and the rolling head
are one atomic record-store update before append acknowledgment. Certificates
come only from the committed local head and remain outside the history they
certify. `serve(transport)` recovers retained evidence and orders eligible signed
wire records from the transport's durable subscription. SQL acceptance remains a
replica decision.

`NativeAgentStore` supplies the same atomic bytes port for embedded native hosts.
It holds SQLite's exclusive owner fence for the lifetime of the connection and
can back `DurableFeedStore`, authoring state, the authority, and checkpoints.
The existing daemon instead shares its already fenced node-state database.

A persistent volume is required. A certificate proves order, not a second
durable copy or an external backup. An unavailable authority pauses new finality;
peers retain local reads and already certified history. There is no automatic
authority or policy failover.

After restoring a volume, establish continuity independently before continuing
the same authority/history. `NativeAuthority.open({ continuity })` and
`CHRONOLOG_AUTHORITY_CONTINUITY_FILE` accept a trusted `{historyId, position,
root}` checkpoint and refuse an older or conflicting retained prefix. A
checkpoint copied from the same old backup cannot detect rollback. Without
established continuity, create an explicit new history lineage. Neither this
package nor a missing newer peer certificate proves that a restored backup was
the latest acknowledged state.

## Trusted application modules

Set `CHRONOLOG_AGENT_MODULE` to a local module exporting `createAgent(context)`.
The public `AgentApplicationModule` and `AgentApplicationContext` types are
exported from `@chronolog/agent-service`. A factory describes its workers and
long-lived connection tasks; it should not wait for final publication during
configuration, before the resident loops start.

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
publisher, optional authority, grant-checked signal setup, and authenticated
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

## Direct and relayed connections

`framePeerStream` adapts a reliable `ReadableStream`/`WritableStream` pair to
bounded length-prefixed frames, backpressure, cancellation, and truncated-frame
errors. Use an appropriate encrypted production transport such as WSS/QUIC; the
framing code is not a replacement for transport security or a NAT traversal
implementation.

`openAuthenticatedPeerLink` adds a mutual nonce/signature handshake bound to
group identity and each participant's active read grant. It creates an ordinary
`FeedLink` for the existing retained feed/evidence pull protocol. It never trusts
rendezvous hints or a relay login as database membership. Every range request
rechecks the receiver's known active grant. A connection can carry records by
other original authors; endpoint and record identities remain distinct.

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
uses `asLink()` and `connect()`. The daemon module context's `connectPeer()`
performs active reader authorization and attaches a framed session to the native
transport.

Peer frames use canonical CBOR with domain `chronolog/peer/v1`; ephemeral frames
use `chronolog/ephemeral/v1`. The session multiplexes bounded range responses,
content-addressed payload responses, change hints, and replaceable signals. Signals cannot hold up retained range
handling. There are at most four pending requests in either direction and each
range is bounded to 64 records / 64 MiB. The event program limit normally makes
actual batches considerably smaller. Connections require deployment measurement
before making direct-connect, relay-bandwidth, or cost claims.

`EphemeralChannel` signs group/topic/grant/session/sequence/expiry and checks the
receiver's current capabilities. It bounds active replay sessions, send/receive
work, and subscriber queues. Slow subscribers receive latest replaceable values.
No signal advances a durable event cursor. An offline receiver cannot know about
a revocation it has not received.

## Signed membership ledger endpoint

`createMembershipLedgerHandler({ authority, descriptor, sink? })`, exported from
`@chronolog/agent-service/membership-http`, serves exact `POST /_chronolog/membership`
requests as raw canonical CBOR. Each request is signed by the genesis roster root
and binds the group, exact history configuration, request, nonce and short expiry.
The native authority key remains separate. The daemon mounts this handler only
when it hosts the group's pinned native authority. The ordinary owner RPC bearer
does not authorize this route; its independently verified signature does.

Reads return every descriptor in a contiguous bounded range and a fresh signed
prefix certificate. They never fetch detached application payloads. Appends
accept only inline capability or epoch records. The native log commits before
acknowledgment, so a lost response returns the same position on exact retry.
When a sink is configured, the handler publishes only the returned entries and
certificate; a later read can heal interrupted evidence delivery. Read pages
carry at most 1 MiB of encoded entries, at most 128 entries, and responses and
requests are capped at 2 MiB. Large recipient wrap lists remain subject to the
explicit inline control limit.

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
