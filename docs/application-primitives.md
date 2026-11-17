# Application primitives, finality and authority

Chronolog is a replicated application log. A signed program can change SQL state
and emit durable facts atomically; an event-only profile runs without SQL. Peers
agree on inclusion, derive one fixed order, and execute locally. A separate live
signal channel carries transient messages and works without that log. Tendriller
supplies hosting and application bindings; it does not implicitly own the peer
database or its trust policy.

This is the entry point for application and agent authors. The protocol details
live in [pluggable finality](pluggable-finality.md) and the
[SQL specification](implementation-specs/10-deterministic-sql-transactions.md).
All formats are pre-release: changed formats reject old input, with no migration
or compatibility layer.

## Choose the primitive by the promise you need

| Primitive | Promise | Typical uses |
| --- | --- | --- |
| `signals.send` / `signals.subscribe` | Authenticated live delivery with expiry and bounded resources. No durable recovery or finality. | Presence, typing, pointers, progress, preview chunks, transient actions, device samples. |
| `submit(program, { operationId })` | One durable signed operation; SQL changes and emitted facts accept or reject together. Exact retries retain identity. | Claims, permissions, task changes, mixed state/event updates. |
| `events.publish` / `events.subscribe` | Durable facts; final readers deliver complete accepted programs with resumable progress. | Conversation, audit, jobs, agent intent, replayable projections. |
| `changes({ view })` + `readView({ view })` | Initial state and coalesced invalidations, then a coherent SQL/event snapshot. | Screens, local optimistic feedback, finality indicators. |

An event-only execution profile runs durable events without loading SQL.
The shipped final event readers require inclusion and finality; a proposal can
be durably retained before either. If recovery is unnecessary, use signals
directly; they are an independent package, not an event-only database.

### Live signals

`@chronolog/signals` depends on WebCrypto and JSON, not Chronolog records,
membership, SQL, validators, or finality. Applications provide a signing identity,
an authorization function, and live routes. Browser peers and resident agents
provide those bindings through `peer.signals`, `client.signals`, and
`context.signals`. Governed peer connections carry replication and signals on
independent reliable and live lanes under one authenticated connection owner.
Closing that physical connection removes both routes. The signal service and
its subscriptions can outlive an individual route and use other attached peers;
a reliable-only connection installs no signal route.

`mode: 'all'` preserves arrival order in a bounded FIFO. A live transport may drop
or reorder messages, so include chunk indices when the application needs to
reconstruct a sequence or detect gaps. `mode: 'latest'` replaces pending state
from the same author, session, and topic. Use it for presence and current progress. Overflow ends a subscription
with an explicit error. Neither mode claims reliable delivery through a
disconnect. A completed send means local dispatch on a live route, not remote
receipt or execution. Reconnect never replays signals.

Signatures preserve the original author through relays. Authorization uses that
author, not the connecting relay or a payload role. Encryption and recipient
admission belong to the transport. Expiry bounds message lifetime; applications
also expire displayed presence. See the [signals contract](../packages/signals/README.md).

### Durable facts and coherent reads

An emit is a literal step of a signed program. If any step fails, the complete
program rejects and contributes no effective events. Stable event IDs identify
the proposal and event ordinal. Every effective event includes `origin` derived
from the verified signed proposal: original author, group, operation ID, writer
capability, membership revision, and author timestamp. Payloads cannot replace
that provenance. A local RPC owner may delegate authoring to its node; the
origin then names that node and its signed, principal-scoped operation identity.

`events.subscribe()` delivers final batches with a cursor bound to the history
and normalized topic filter. Persist projection state and the **processed**
cursor atomically. A cursor received in memory is not a committed checkpoint.
Use `DurableProjection` for pure replayable caches. Do not send external requests
from a reducer or replay callback.

If the event runtime loses a storage acknowledgment, it refuses further mutation
until reopened: the write may have committed, so replacing it from older
in-memory state would be unsafe. Default `readView()` and durable event readers
use the final view; choose `local` explicitly for speculative state.

## Observe and capture an application view

`node.changes()` and `client.changes()` start with the current applied **final**
view. Use `{ view: 'local' }` for a display that intentionally includes
speculative state. Each notification is `{ view, revision, finalRevision }`,
using the same opaque tokens as `readView()` and its event reader. Tokens identify
this replica's applied snapshots; they are not global sequence numbers, finality
proofs or values to parse or order.

The stream emits after successful application reconciliation. SQL-only changes
and changed outcomes during replay invalidate the local view even when they
emit no event. Admission, transport and heartbeat bookkeeping alone do not.
Final subscriptions remain quiet while only speculative state changes. A local
subscription also reports final-prefix advancement, which can change
`finalRevision` without changing its local `revision`.

These notifications are bounded, coalesced refresh requests. A slow consumer
receives the latest snapshot identity and can miss intermediate ones. There is
no history cursor; the client reconnects by obtaining the current identity.
Reading tokens acquires no SQL snapshot lease, does not scan event outcomes,
and does not poll the page host.
Capture a read view when ready to render, and release it afterward. The captured
view may be newer than the notification, so its own tokens describe the data
being displayed. SQL and `readEvents()` on that handle remain pinned together.

During incomplete or ambiguous publication, a view whose underlying counters
have advanced without successful reconciliation is unavailable. A genuinely
unchanged final view remains readable. Change streams wait for a usable applied
snapshot; they never relabel partially published state with an older token.
Returning or throwing from the iterator, aborting its signal, or closing its
owner releases idle and paused subscriptions.

Use `events.subscribe()` with a processed checkpoint when every effective final
event must be consumed, including after reconnect. Use `signals.subscribe()`
for expiring live messages. Neither is a substitute for application view
invalidation: SQL-only replay may emit no event, and signals do not establish
what durable state this replica has applied.

## Submission, replay, and finality

A transaction has two independent properties:

| Property | Values | Meaning |
| --- | --- | --- |
| Lifecycle | `queued`, `provisional`, `final` | How stable the observed result is. |
| Outcome | `accepted`, `rejected` | What executing the program did. |

Before materialization the outcome is pending. Both acceptance and rejection
can be provisional. A final rejection is a completed operation and retires its
outbox entry just as final acceptance does.

For Chronolog handles:

```ts
const change = await client.submit(program, { operationId })
const preview = await change.provisional({ signal }) // Can change during replay.
const outcome = await change.final({ signal })       // Final acceptance or rejection.
await change.accepted({ signal })                    // Throws on final rejection.
```

Use `accepted()` before dependent durable intent. The node assigns new author
time after its applied observations and verified closed frontier, even if the
wall clock regresses. Applications do not repair timestamps or manufacture
validator evidence. Persist the operation ID before submission and reuse the
same program for exact retries. A retry recovers the original signed proposal,
timestamp, outcome, and revocation context. A changed program needs a new ID.
Cancelling a waiter does not cancel an already published operation.

Reopening reconstructs the automatic author-time floor from retained proofs and
successfully applied history. Merely receiving an unadmitted proposal does not
advance it. Preserve an original observation time as application data instead
of calculating ordering timestamps. Governed authoring uses the maximum future
skew in signed genesis. If advancing the automatic clock would exceed that bound,
new authoring fails with `AUTHOR_CLOCK_AHEAD`. Correct the clock before trying
new intent again; an exact retry of a prepared operation keeps its original
bytes and timestamp.

In a signed-inclusion history, a proposal first included after its author
timestamp closes receives `FINALITY_TIMESTAMP_CLOSED`. Excessive future
timestamps receive `FINALITY_TIMESTAMP_FUTURE`; admissible future proposals
wait for closure. Fixed validators withhold votes outside their future window
and reconsider those proposals on heartbeat clock progress. A proposal becomes
finally excluded only when no remaining legitimate admission is possible.
Silently re-signing either rejected proposal would change its identity and
meaning. Trying again is an explicit new operation with current assumptions.

### One execution order

All providers use `(author timestamp, author public key, proposal ID)`.
Transport feed sequence is a replication concern. Receipt order is an inclusion
concern. Neither is an application sort key. A late eligible predecessor can
change a tentative suffix: restore the nearest checkpoint, replay pure programs,
and publish one coherent replacement view. Do not append the replacement events
to an earlier speculative projection as if they were new final facts.

Finality proves that no eligible predecessor can still change a prefix. The
replica must also have the records, keys, and execution profile needed to apply
that prefix. Missing input or a storage failure blocks progress; it does not
invent a SQL rejection. `accepted()` and `final()` wait for the locally applied
result, not merely a receipt or a clock observation. A final replica can still
be behind another replica.

The fixed-validator provider uses signed decisions and closure promises over
complete authenticated feed prefixes. Partial earlier admissions must be
resolved before later work is final. The signed-inclusion provider uses a
certified retained set and explicit author-time closures. Its service can
certify inclusion without decrypting SQL. A custom provider must prove the same
inclusion and closed-prefix contract; it cannot supply a different comparator.
The current extension port normalizes the signed-inclusion receipt/closure proof
family. It does not implement arbitrary consensus providers or dynamic signer
reconfiguration.
The detailed trust and liveness rules are in [pluggable finality](pluggable-finality.md).

Peer catch-up has a finite boundary: it captures retained feed and evidence
heads and copies through those positions. Publication may continue while that
copy finishes. Later hints or another catch-up collect the new tail. Catch-up
does not promise that every application input is available or that a final
target has been applied; materialization and finality are separate checks.
Availability heads carry no extra authority.

Historical evidence is processed in bounded batches. A transport commits a
received evidence page before making it available; the node verifies each proof
and publishes the resulting coherent application prefix once per batch. A fresh
replica therefore does not have to publish every intermediate database revision
from the original session. Batching changes neither transaction boundaries nor
finality rules. A directly ingested single proof still reconciles immediately.

### Rollback, redo, and user undo

The current node executes admitted proposals. Its `provisional()` result means
that the executed ordering or outcome can still change before finality; it does
not promise execution before admission.

Admission and local selection are different facts. Admission is permanent;
the local materializer can replace an unfinalized selection while replaying it.
Removing a selected preview removes its current outcome, not its retained signed
proposal. A proposal that remains selected keeps its original identity, and an
established final prefix cannot be removed or changed. Both the SQL and event-only
runtimes enforce the same chronological order and final-prefix rules.

The Tendriller application port reports lifecycle separately from outcome. A
rejection can be provisional; once immutable it is `status: 'final', outcome:
'rejected'`. An exact retry recovers that final rejection without creating a new
operation or waiting for another finality decision.

Use final reads by default for shared business state. Use a local view when the
UI intentionally presents speculative state and can replace it after replay.
Not every locally submitted proposal is immediately in the local materialized
view: admission and required inputs can still be pending. Wait cancellation
stops the caller's wait and leaves a prepared durable operation intact.

Protocol replay replaces speculative local state. It cannot roll back an
external email, payment, or device action, so those actions start only from
final accepted intent. Redoing deterministic materialization does not rerun
external providers. The owning node recovers retained operations from its journal
and feed; catch-up and explicit same-ID retries reuse the original signed bytes.
A frontend reconnection cannot recover intent that its owner never retained.
Client request retries are bounded and do not create an offline intent queue.
Reconnection never replays a live signal.

User undo is a new authorized compensating program, with a new operation ID and
guards against the current state. It does not delete signed history or restore
a stale database image. If another user changed the target, the guard can reject
the undo. Redo is another explicitly guarded intent. Application-specific undo
rules belong in the application, not the consensus or transport layer.

## Authority is a set of named roles

| Role | Controls | Does not imply |
| --- | --- | --- |
| Tendriller page host | Hosting, page lifetime, transport binding | Peer database ownership, membership administration, or finality authority. |
| Membership administrator | Signed enrollment, capabilities, key grants and revocations | Ownership of every application row or permission to run every external action. |
| Schema administrator | DDL and application constraints | Permission to bypass owner-controlled row writes. |
| Writer | Exact SQL/topic/signal rights from its grant | Finality, administrator status, or authority asserted in payload text. |
| Finality provider | Inclusion and closed-prefix evidence under genesis policy | Application semantics, row ownership, or a choice of execution order. |
| Replica | Verifies original proofs and materializes local views | Authority to rewrite another author's identity or replace the provider. |
| Resident effect handler | Explicit delegated application actions | A general right to obey every event or signal it can receive. |

`NativeFinalityService` is the concrete native signed-inclusion service. Agent
modules receive `context.finality` when this process hosts it, or `null` when it
does not. There is no catch-all `context.authority`. The provider identity and
configuration are authenticated by genesis; transport discovery never chooses
them implicitly. The replica-side `LiveInclusionFinalityProvider` verifies
receipt and closure proofs; effect modules normally use `context.publisher`,
`context.signals`, and final-event handlers.

Membership administration is pinned by genesis's `rootAdminPublicKey` and
`capabilityLogFeed`; it is not a grantable capability role. Reader, writer and
validator grants have separate jobs. Every writer declares its exact `program`
rights: SQL permission, durable topics and ephemeral signal topics. Missing
rights never imply SQL permission, and one exact grant must cover the operation.
RPC grant requests and status expose those same rights for agents to review.

The convenience native bootstrap explicitly grants several roles to its owner.
That is visible bootstrap policy, not an implication of being a resident process.
A separately provisioned membership host may pin a different finality key and
schema administrator. An agent on an ordinary enrolled replica can consume final
events without hosting the finality service.

The built-in signed service assumes the configured signer honors its promises
and its durable history is not rolled back. Fixed validators assume the selected
quorums honor their promises. An unavailable required provider pauses finality;
it need not stop independent live signals under already known permissions.
There is no automatic authority rotation, validator reconfiguration, or failover.
Recovery requires established continuity or an explicitly new history lineage.

Effective durable events carry `event.origin` from their verified signed
proposal: the group and signing key, original operation ID, membership revision,
writer capability (or `null` for static membership), and exact signed author
timestamp. The same provenance accompanies event reads, subscriptions and
captured read views. Keep it attached when projecting an event or presenting it
to an agent. Payload fields named `author`, `role`, `origin` or `instruction`
remain application data; they cannot replace authenticated provenance or grant
tool permissions. Historical authorization is not a claim that a grant remains
active now, and authentication alone does not authorize every requested effect.

Participant administration receives compact finalized controls and a signed
completeness checkpoint, without application descriptors or bodies. The same
closure commits that control projection; full replicas recompute it from the
complete history. Newly enrolled peers can bootstrap their current grants and
keys from these proofs, then obtain application history through authenticated
peer replication. See [compact membership proofs](membership-control-proofs.md).

## Bootstrap and run a finality service

Create and persist the signer identity first. Provision signed genesis with its
public key and history ID, the membership and schema administrator identities,
the execution profile and the clock policy. Then open the service using the
verified public descriptor and the signer's private identity:

```ts
import { NativeFinalityService } from '@chronolog/agent-service'

const finality = await NativeFinalityService.open({
  descriptor,       // authenticated genesis + history + group route
  identity,         // the private key matching the pinned finality signer
  store,            // one fenced durable owner
})
await finality.serve(transport, shutdown.signal)
```

`open` verifies the descriptor and derives cutoff lag, maximum future window
and closure interval from signed genesis. Callers cannot accidentally combine
one group's genesis with independent local timing defaults. Governed peer
validators use the same authenticated clock policy. The daemon can set it when
creating genesis; changing it on a continuing group fails explicitly.

There is no bootstrap cycle: membership provisioning needs the finality public
key and chosen history ID, not a running service. `ReferenceRecordLog` remains a
generic opaque retained log and does not require a group descriptor.

The private data volume must retain the signer's complete acknowledged history.
On recovery, supply an independently trusted continuity checkpoint when one is
available. A checkpoint restored from the same stale backup cannot establish
that no later promises existed. A missing or conflicting established log is a
hard continuity error. Finality pauses while its selected service is unavailable;
existing final reads and live signals can continue over connected peers.

## Agents act on authorized final intent

Agent code is ordinary trusted application code. Keep provider credentials and
private reasoning in the agent's private store. A topic filter is not a secrecy
boundary. If publishing to a narrowly scoped intent topic itself grants an action,
make that delegation explicit in the grant and handler contract.

Every effective event carries `origin` derived from its verified signed
proposal, separate from `payload`. Chronolog supplies `kind: 'chronolog'`, the
group, author, operation ID, signed author timestamp, membership revision and
exact writer capability. The author is a lowercase hex signing public key,
matching `Signals.authorId`; group, membership and grant IDs are canonical
base64url strings. The timestamp is an exact decimal string. A null grant means
explicit static membership, not an inferred broad grant. RPC, captured views,
the Tendriller adapter and effect checkpoints preserve these facts on restart.

Publication rights establish who could author an event. A final event does not
by itself authorize every action an agent can perform. Before dispatch, the
handler applies its own policy to `event.origin`, topic and bounded intent; a
payload's `role`, `authorId` or `origin` field is ordinary untrusted data. The
worker's signing identity, provider credentials and tool permissions remain
separate. Revocation cannot rewrite a prior final outcome. A handler may deny
future execution under current application policy, but it must still reconcile
an uncertain provider call that was already dispatched.

The database can make an intent final and persist a worker's state. It cannot
atomically commit another provider's action. Use one designated worker per
handler with an explicit recovery contract.

Use `DurableEffectWorker` for recovery-sensitive actions. It checkpoints intent,
dispatch state, provider result, and processed event progress. Recovery must use
the provider's real idempotency guarantee, provider reconciliation, or an
explicit uncertain state. A local operation ID alone does not create exactly-once
external effects. Use one designated worker per handler. Independent worker
stores need an explicit ownership arrangement; a local file fence is not a
distributed lease. Result publication is an exact retry and waits for final
acceptance before processed progress advances.

A proved final rejection of result publication pauses the effect worker in
`publication-rejected`, with the completed provider result retained. Inspect
`status()` and correct the cause, then explicitly call
`retryPublication(effectId)` to authorize a new publication attempt. This never
repeats the external action. An ambiguous or lost response keeps the same
attempt and operation ID. The eventual `effect.completed` event carries the
rejection audit; each effect permits at most 64 publication attempts.

Timers publish ordinary final intent, with durable generation IDs and guarded
cancellation. A rejected publication pauses the scheduler with its original
occurrence intact; `retryPublication(occurrenceId)` explicitly allocates a new
guarded attempt. An uncertain reply keeps the old attempt. Rechecking the same
generation and due time prevents recovery from reviving a cancelled schedule or
duplicating an accepted occurrence. The successful event carries rejected-attempt
audit, and `publicationStatus(occurrenceId)` retains local audit even when the
final outcome is cancellation with no event. Timers do not execute provider code
from a clock callback. See the
[resident agent guide](../packages/agent-service/README.md) for the actual module,
worker, timer, signal, and peer APIs.

## Evidence and release surfaces

- The standalone signals package is built, checked for zero runtime imports,
  packed, and included in quality/release artifacts with source provenance.
- The client, RPC, browser peer, and resident service expose the same live signal
  interface. Governed transport tests relay original signed frames through three
  peers without reading durable history.
- Application integration tests cover atomic SQL/events, final rejection,
  provisional rebases, interrupted publication, coherent pinned views, finality
  invalidations, provenance after restart, and atomic projection checkpoints.
- Provider tests exercise proof gaps, partial quorums, late admission, rejection,
  exact retries, missing keys/bodies, monotone closure, and recovery.
- Tendriller consumers use packed SDK/runtime/engine artifacts; contrib recipes
  exercise the public APIs. Historical reports retain their original versions
  and do not qualify a changed protocol.
