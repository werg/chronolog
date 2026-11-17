# Application primitives, finality and authority

Start with the guarantee the application needs. Chronolog offers a live message
path and a durable application log. Signals can be used on their own. The default
Tendriller application mode is live collaboration: signed timestamp ordering,
deterministic replay, and a provisional suffix above an immutable final prefix.
SQL is an optional execution profile of that log. A future asynchronous
branch/merge mode can share signed operations, timestamp ordering and replay;
it has no finality concept, API or provisional/final states. It would define its
own inclusion and merge rules and is not implemented by the live API.

## Choose the primitive

| Need | Primitive | What the caller gets |
| --- | --- | --- |
| Typing, presence, cursors, live progress, previews, telemetry whose loss is acceptable | `signals.send(topic, payload)` | A signed, expiring live message. No persistence, retry outbox, replay, transaction or finality wait. |
| Chat, an audit record, a durable command or a completed result | `events.publish(topic, payload, { operationId })` | A durable proposal. Effective events are exposed after final acceptance. |
| A change that must preserve an invariant, or a state change and event that must agree | `submit(program(...), { operationId })` | One atomic SQL/event program, with a durable accepted or rejected outcome. |
| Payment, email, a provider call or another irreversible action | A final intent event and one designated effect worker | Durable dispatch state plus an explicit provider idempotency, reconciliation or manual recovery contract. |
| A local display/cache derived from durable events | A checkpointed projection | Rebuildable state and processed progress committed together. |
| Refresh a screen after applied SQL, events, replay or finality changes | `changes({ view })` followed by `readView({ view })` | The current applied view identity, then coalesced invalidations; each captured read remains coherent until released. |

Ephemeral does not mean restricted to presence. Choose signals whenever losing
an individual message, missing messages while disconnected, and receiving a
newer value are acceptable. Persist the final result separately when it matters.
An action that must happen after reconnect is a durable intent, even when it
does not need SQL.

```ts
// These return different guarantees deliberately.
await client.signals.send('typing', { active: true }, { ttlMs: 3_000 })

const message = await client.events.publish('conversation', {
  text: 'The analysis is ready.',
}, { operationId: durableMessageId })
const final = await message.final()
if (final.outcome.type === 'rejected') handleRejection(final.outcome.rejection)
message.dispose()
```

The standalone [`@chronolog/signals`](../packages/signals/README.md) package
depends on canonical encoding, not the database protocol, capabilities,
membership history, finality or an SQL engine. Its explicit authorization callback
can use the application's own session or credential policy. The Chronolog group
adapter checks active signal-topic rights; it still does not submit a ledger
record. Native and browser replicas expose the same `client.signals` API and
attach it to their live peer connections.

Signal listeners choose `mode: 'latest'` for replaceable state such as a cursor
or progress value. The bounded `all` mode preserves messages accepted into that
live subscription; it does not promise network delivery or reconnect replay.
Neither mode provides a durable command queue. Cancellation or a send timeout
does not prove a remote callback did not run. See the signals package for exact
limits, loss, ordering, authorization and encryption semantics.

## What finality means

There are three decisions:

1. **Validity:** original signatures, group, execution profile, grants and the
   program are valid.
2. **Inclusion:** the selected provider proves which original records belong
   to this history.
3. **Finality:** a verified author-time closure proves that later first
   inclusions cannot insert a proposal into the closed chronological prefix.

Every replica derives the application order from signed author timestamp,
signing public key and stable proposal ID. The transport arrival order and the
provider's receipt positions do not order application execution. A provider
can affect which records are included; it cannot choose a different comparator.

The selected provider proves finality; the local replica must also obtain and
verify the required records, bodies and keys, then apply the prefix. A receipt,
an open RTC connection, or knowledge of a newer certificate alone does not mean
the application has applied that state.

| Observation | Meaning |
| --- | --- |
| `submit` / `events.publish` returns | The original proposal has been durably published locally. |
| `handle.local()` returns | A current accepted or rejected result; it may still change through replay. |
| `handle.final()` returns | An immutable locally applied accepted **or rejected** result. Inspect `outcome.type`. |
| A final read view exists | A coherent snapshot of this replica's applied final prefix. It may lag another replica. |
| `signals.send()` returns | Local live dispatch completed; it has no relationship to durable finality. |

The Tendriller application port reports lifecycle separately from outcome. A
rejection can be provisional; once immutable it is `status: 'final', outcome:
'rejected'`. An exact retry recovers that final rejection without creating a new
operation or waiting for another finality decision.

Use final reads by default for shared business state. Use a local view when the
UI intentionally presents speculative state and can replace it after replay.
Local execution does not wait for a receipt or validator quorum. It can still
wait for authorization, acceptable clock bounds or required inputs. Wait
cancellation stops the caller's wait and leaves a prepared durable operation
intact.

Author dependent work after observing its prerequisite's final accepted result,
and keep the required business guards in the new program. Automatic timestamps
advance past the replica's successfully applied history and verified closed-time
frontier, even when its wall clock trails another writer. Reopening reconstructs
that floor from retained proofs and application history. Merely receiving an
unadmitted proposal does not advance it, and it creates no dependency on unseen
work. Applications should preserve an original observation time as domain data
instead of calculating ordering timestamps.

Governed authoring uses the maximum future skew in signed genesis. If advancing
the automatic clock would exceed that bound, new authoring fails with
`AUTHOR_CLOCK_AHEAD`; it does not change the requested operation or its guards.
Correct the clock before trying new intent again. Retrying an already prepared
operation preserves its original timestamp and bytes.

Signed genesis selects the trust policy. The built-in validator policy needs
the specified validators' admission and closed-time evidence. The built-in
signed-inclusion policy needs one pinned finality signer and its continuous
retained history. Both are P2P replication systems. The second policy deliberately
trades finality availability for a simpler single-service trust model. A signer
can withhold inclusion; contradictory authentic promises are continuity errors,
not a reason to silently select another history. There is no automatic signer,
validator-set or provider replacement.

Peer catch-up has a finite boundary: it captures retained feed and evidence
heads and copies through those positions. Publication may continue while that
copy finishes. Later hints or another catch-up collect the new tail. Catch-up
does not promise that every application input is available or that a final
target has been applied; those remain explicit materialization and finality
checks. Availability heads carry no extra authority.

## Replay, retries, redo and undo

These operations have different meanings:

| Operation | Identity and behavior |
| --- | --- |
| Retry a request whose response was lost | Reuse the exact `operationId` and program. Recover the original proposal and outcome. |
| Replay after learning an earlier admitted proposal | The replica recomputes the provisional suffix in deterministic order, preserving original proposal identities. |
| Redo a business action after a final rejection | Make a deliberate new proposal with a new operation ID and current assumptions. The old rejection remains final. |
| Undo a final change | Submit a new compensating transaction. Final history is not erased or rolled back. |

A locally authorized proposal may be selected for preview before consensus
admission. That unadmitted preview can be removed when the proposal is excluded
or loses authorization. Admission is a separate immutable inclusion decision:
an admitted proposal cannot be removed or replaced, but its application result
can remain provisional.

A late proposal may change a provisional SQL outcome from accepted to rejected,
or rejected to accepted. The materializer returns to a checkpoint before the
affected suffix, re-executes pure programs and atomically publishes the new
view. Events from rejected programs are suppressed. An established final prefix
cannot change. The SQL-free event materializer preserves original proposal
bytes and that final-prefix boundary while allowing unadmitted previews to leave
the selected suffix.

An uncertain storage acknowledgment requires reopening the event runtime before
more replay or finality publication. A write may already have committed; it is
unsafe to overwrite that stored prefix from older in-memory state. Reopening
recovers the committed operation identities and final boundary.

The UI replaces a complete captured view after a rebase; it must not accumulate
irreversible side effects from speculative event callbacks. Capture SQL and
events through one `readView()` when displaying them together. The capture pins
one locally applied application prefix: its SQL rows, effective events and
revision metadata agree even if new proof or replay arrives during rendering.
Release the read lease after rendering. Durable projections and effect workers
consume the final event stream using stable event IDs and processed checkpoints.

A backdated proposal first included after its timestamp is closed receives
`FINALITY_TIMESTAMP_CLOSED`. Re-signing it silently under a new timestamp would
change its meaning. Exact retries still recover the original result. If the
user wants to try again, create a new operation explicitly. Excessive future
timestamps receive `FINALITY_TIMESTAMP_FUTURE`; a timestamp within the signed
future window waits until its time closes.

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

## Give each authority a precise job

Co-location is a deployment choice. These are separate permissions and roles:

| Role | Owns | Does not acquire implicitly |
| --- | --- | --- |
| Membership administrator | Signed grants/revocations, reader-key delivery and roster history | Application writer rights, SQL ownership or the finality signing key |
| Schema administrator | Initial schema-administration authority authenticated in genesis | Membership administration, reader keys or arbitrary ownership of other users' rows |
| Finality service | Inclusion receipts and closed-time promises for one pinned history | Permission to author application writes, administer membership, read encrypted bodies or execute external effects |
| Replica | Verification, local durable state, replay and reads permitted by its grants | Finality signer, membership administrator or effect-worker status |
| Designated effect worker | One handler's durable processed checkpoint and provider dispatch/recovery | Distributed exactly-once execution merely because peers share a log |
| Page host / introduction service | Assets, account access and bounded connection introductions | Database membership, execution order or application finality |

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

The public proof producer is **`NativeFinalityService`**. A **`LiveInclusionFinalityProvider`**
is the replica-side verifier of proof bytes. `AgentApplicationContext.finality`
is non-null only where this process hosts the selected signer. Effect modules
normally need `context.publisher`, `context.signals` and their final-event
handlers, not direct access to the service.

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

## External effects are a separate boundary

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
handler and select one explicit recovery contract:

- Provider idempotency: send the worker's stable `idempotencyKey` unchanged.
- Provider reconciliation: query the uncertain operation before redispatching.
- Manual resolution: stop on an uncertain external result until an operator
  supplies a decision.

The worker durably records dispatch state before calling the provider, retains
the result before publishing its final result event, and retries publication
without dispatching again. Multiple processes on independent stores still need
an explicit ownership arrangement and the provider's recovery contract. A
local file fence is not a distributed lease. Pure SQL/event replay never calls
provider code.

## Implementation map

- [Signal contract and standalone usage](../packages/signals/README.md)
- [Client views and transaction handles](../packages/client/README.md)
- [Finality proofs, controls and provider extension](pluggable-finality.md)
- [Compact membership proofs and peer bootstrap](membership-control-proofs.md)
- [Resident effects, timers and recovery](../packages/agent-service/README.md)
- [Native continuity and crash recovery](authority-recovery.md)
- [Browser Worker ownership and peer connections](../packages/runtime-browser/README.md)

The current custom-provider port uses the signed-inclusion proof family and
normalized receipt/closure snapshots. It is an extension point for a verified
inclusion policy, not a claim that arbitrary consensus engines or automatic
authority failover are implemented. The record and transport layers remain
independent of that choice.
