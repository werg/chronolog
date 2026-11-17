# Peer application architecture

The default shared-application composition uses `peer-generation-v1`. Chronolog
owns signed commands, deterministic local execution, live signals, encrypted
content and peer recovery. Tendriller serves the initial application and acts as
a constrained control participant. A browser Worker and a resident native
process use the same authenticated history rules.

The host is small in data volume, but its generation registry is an authority:
it durably selects one successor against an expected generation. Ordinary
collaboration continues without it; creating or changing that selection needs
its control service. A directory entry or an open transport grants no authority.

## Participants, policy and transports

A participant combines an identity, explicit protocol rights, the record types
it handles, and durable resources it owns. The current host role is
`controlParticipantGrant`: administrator and recovery rights, no application
reader, writer, coordinator or data-collective membership. That is a protocol
role, not a special all-powerful replica.

| Participant | Receives and retains | May publish or select |
| --- | --- | --- |
| Hosted control participant | Public application definition, signed schema, control revisions, generation selections and bounded prefix proofs | Authorized membership/control changes and compare-and-swap successor selections |
| Browser Worker | Its private keys, authorized epoch keys, complete verified selected history, original saved commands and requested content | Commands and signals allowed by its grants; order receipts only when selected; recovery requests when eligible |
| Resident native peer | The same application evidence in an independent durable store | The same explicitly granted actions; being continuously online adds no authority |
| Page or local tool adapter | Captured application views, operation status, recovery notices and explicitly requested content | Validated domain commands through the owning session |

Transport adapters provide delivery, framing, backpressure, size limits and
connection lifetime. Protocol admission verifies signatures, scope, current
rights and the relevant history rules. Keep these concerns separate: routing
should avoid transmitting irrelevant or forbidden data, and admission must
reject it even when a different route delivers it.

The current adapters deliberately differ. Hosted controls use bounded HTTPS
requests to a durable registry. Application sessions use authenticated WebRTC
lanes. Both consume Chronolog's public signed structures and verification rules;
the hosted registry does not load SQL, application callbacks or a full replica.
Adding an adapter should not require another authority implementation.

## One protocol family, explicit semantics

Sharing identity, encoding, verification and transport machinery does not make
all updates interchangeable. The receiving participant dispatches each record
to a small handler with its own storage and consistency requirements.

| Record family | Ordering and retention | Recovery meaning |
| --- | --- | --- |
| Application commands and durable events | Original encrypted signed attempts, ordered by the selected generation and executed deterministically | A successor may adopt an older complete prefix. Available excluded work is quarantined. |
| Membership, key epochs and generation selection | Signed monotonic controls; controls and their activating generation commit together | Application rollback cannot restore a revoked permission or an old key epoch. |
| Live signals | Bounded authenticated messages with expiry, no durable outbox and no replay cursor | Reconnection sends current activity; expired activity is discarded. |
| Attachments | Immutable encrypted chunks, content commitments and complete-retention acknowledgments | Missing chunks remain visibly unavailable. Receiving a reference does not claim retention. |
| Application definition and SQL initializer | Public schemas and exact initializer bytes authenticated by the descriptor and schema signature | Ordinary commands cannot replace the definition, execution profile, schema or ownership policy. |

Application code declares domain commands, input schemas and queries once.
Hosted metadata and local tools consume the same validated public description
and digest. The executing session validates inputs and turns a command into its
change program. The host does not execute the domain callback.

## Authority and ownership

The descriptor pins the application/history identity, control key, definition,
execution manifest and schema authority. A signed generation delegates ordering
to an eligible reader. Delegation does not authorize that reader to impersonate
an author or edit another owner's rows.

Shared SQL rows belong to the application collective. Its membership is derived
from verified control revisions, independently of which device coordinates.
Replay uses historical controls for inherited commands and current controls for
new commands. Restrictive controls remain effective when application state rolls
back. Protected schema, ownership and policy changes cannot travel as ordinary
lossy edits.

Device signing keys and retained epoch keys belong to the Worker or native
device owner. A newly granted reader requests missing keys from a current data
peer using a signed, generation-bound request and a fresh ephemeral HPKE
receiver. The reply is encrypted for that receiver and checked against the
authenticated epoch commitments before durable installation. The host has no
parallel key-delivery store. Reader enrollment, writer authority, coordination
eligibility and recovery permission remain distinct rights.

## Cold start and quiet steady state

1. Tendriller serves the page, public application description and initial routing
   hints. The initial asset delivery is separate from application replication.
2. The owning Worker or native device opens exclusive storage, verifies the
   pinned descriptor and control chain, and obtains its authorized epoch keys.
3. An introduction exchanges the transport offer with a reachable peer. The
   application session authenticates the peer independently of that offer.
4. Peers exchange original command evidence, bounded captured history ranges,
   live signals and requested content. The host receives no application bodies.
5. Explicit lifecycle actions refresh controls or routing when needed. Healthy
   application sessions require no host polling or application keepalive timer.

A cold device may need the host to discover and enroll. A connected pair can
continue authorized collaboration while host access is blocked. A device cannot
know a revocation or successor it has not yet received; reconnect verifies new
control evidence and reconciles the selected history instead of pretending that
a partition provided instantaneous global revocation.

## Outcomes, recovery and retention

A saved command has durable original bytes and an operation identity. Applied
means the selected history produced an accepted or rejected execution result;
shared means another storage owner acknowledged a retained prefix. Neither word
promises irreversible finality.

A captured view binds commands to the generation and history point the caller
observed. A recovery switches SQL, effective events, outcomes and view revision
together. Excluded views cause an explicit reread/reset condition. Quarantined
work is never automatically resubmitted. Deliberate reapplication creates a new
attempt under current authority and freshly evaluated domain guards.

A successor adopts a prefix of the currently selected history. Once that choice
excludes an old suffix, a later successor cannot resurrect it, even when the old
records carry valid signatures. The same `PeerAuthority` verifier enforces this
rule in browser, native and hosted control runtimes.

Retain complete replayable evidence initially. A SQL cache, an advertised last
seen time or a signed checkpoint without its original bodies is not a recovery
source. Prompt replication aims for an independently stored complete prefix;
reports distinguish known abandoned work from unknown loss.

The public application waits are `applied()` for the selected execution result
and `shared()` for independently retained coverage. Their names and guarantees
are the same in the session, Worker facade and local tools. A future change in
completion vocabulary would require an explicit API decision; it is not part of
this implemented contract.

External-effect consumers need reset-aware projections, a retained dispatch
journal, stable provider retry identities and reconciliation of uncertain calls.
The current append-only consumers still need that integration. Protect a complete
prerequisite program and its dependencies only when the application requires them
to survive recovery. See the [integration details](plans/peer-generation-integration-details.md).

## Extending the same machinery to code and page updates

The protocol boundaries above support a useful next step: immutable code/assets
in the content layer, a signed release record naming their digests, and live
signals for transient editing/preview activity. That would let a hosting
participant subscribe to approved releases and materialize the page assets it
serves, while ignoring ordinary application commands.

This is an extension direction, not a claim that the current publishing service
has already moved into Chronolog. A release protocol needs explicit publisher
rights, monotonic release selection, content availability and activation rules.
Approving a release and executing its JavaScript are separate decisions. An
application-data recovery must not silently downgrade its code or restore a
revoked publisher.

Release content also needs its own visibility and key scope. The current
attachment API authorizes application readers; granting a publishing host that
right merely to serve page assets would also grant access to application
content. Public releases or a separate release collective can reuse the content
machinery while keeping private application epoch keys out of the host.

The current descriptor pins the application definition and execution profile.
Changing either requires an explicit supported history/version boundary; a page
cannot reinterpret retained commands with arbitrary new code. The initial
verifier and trust root also need a bootstrap channel before peer content can be
authenticated. HTTP can continue serving that small shell even when subsequent
release exchange shares Chronolog's content and control mechanisms.

Prefer these concrete record families and handlers over an extensible framework
of transport-specific authorization callbacks. Add the shared abstraction where
two real consumers need it, with policy enforcement at the protocol boundary.

## Qualification

Meaningful evidence includes signed recovery model traces, encrypted deterministic
replay, restrictive controls surviving rollback, lost durable acknowledgments,
interrupted tails, independent storage, packed public consumers and real RTC
connections. Browser qualification additionally exercises the owning Worker,
OPFS, competing storage owners and reload.

Loopback and local workerd runs establish those measured paths only. Internet
connectivity, TURN deployment, browser suspension, provider cost and a sustained
production operating envelope need separate measurements. Do not infer them
from an installed backend or a successful simulated connection.

See [peer-generation authority](peer-generation-v1.md),
[the public application session](../packages/peer-session/README.md),
[portable history](portable-peers.md) and
[WebRTC transport](../packages/transport-webrtc/README.md).
