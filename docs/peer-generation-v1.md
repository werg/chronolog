# Peer generations: selected history with tolerant recovery

Status: the portable control service, encrypted peer replica and owned application
session are implemented. The packages include event replay, native SQL replay,
durable attempt retry, captured views and explicit recovery over in-process or
authenticated framed connections, with browser/native RTC adapters. Native and
in-process tests exercise these surfaces; they do not establish Internet connectivity or a
production recovery-loss bound. This profile does not change the default live
collaboration integration.

The authenticated profile is `peer-generation-v1`, with the bounded
`eligible-members-v1` authority policy. It has no concept of finality. It is
separate from the live profile's chronological inclusion finality.

## Inclusion and application order

A signed generation delegates inclusion to one replaceable peer. The coordinator's
receipt sequence authenticates a chain of included proposal references; generation
selection chooses which receipt prefixes belong to the history. That sequence is
an evidence position, not an application execution order.

Application replay uses the shared Chronolog comparator: the original signed
author timestamp, signing public key, then stable proposal ID. Selecting a receipt
prefix supplies a proposal set to that comparator. A later receipt can include an
earlier timestamp, so it can change application order and outcomes even within the
same selected generation. Neither a receipt position nor a recovery floor closes
author time or establishes an immutable application prefix.

Fresh replica-authored intent uses the shared `nextAuthorTimestampMs` helper to
allocate a timestamp after both this device's prior authored work and its observed
applied work, even when the wall clock has not advanced. This is causal timestamp
allocation, not an inclusion or finality rule. Exact retries retain their original
timestamp and signed bytes. The live profile applies its separate signed clock
bounds outside that helper.

The control participant retains signed descriptors, monotonic controls
and generation selections, and atomically chooses successors. It verifies prefix
proofs and delegated inclusion headers without application bodies or SQL. It does
not authenticate or execute encrypted application proposals. `PeerReplica` verifies
the original authorship, authorization, encryption and execution manifest before
deterministic replay. A coordinator's receipt proves inclusion, not a trusted
execution result.

The control model trusts the control service not to equivocate and assumes one
exclusive durable owner of its store. Its compare-and-swap does not implement
Byzantine consensus or distributed storage consensus. Cached delegations have no
heartbeat renewal requirement. The replica detects conflicting coordinator
receipts and fences further local ordering. A returning old coordinator's excluded
suffix remains outside the selected history; possession of that signed suffix
does not restore its authority.

## Separate authority concerns

| Concern | Contract |
| --- | --- |
| Authorship and authorization | Reader/writer grants identify permitted signers in the attempt's selected control context. Replicas verify the signed proposal and the execution engine enforces its separate SQL policy. |
| Inclusion | A signed generation delegates receipt sequencing to one eligible reader. This grants no author or SQL administrator impersonation rights and does not change the application comparator. |
| Recovery | The requester needs explicit recovery permission; the candidate separately needs coordinator eligibility. A stored replica or writer grant alone is insufficient. |
| Control changes | An authorized administrator can request a signed control revision through generation selection. Schema authority is pinned separately. |
| Shared SQL data | `dataRole: 'member' \| 'admin' \| null` selects membership in the reserved application collective. It is independent of control administration and does not grant schema authority. |
| Retention | A signed retained-prefix acknowledgment reports a complete stored copy. It grants no authority, provides no finality and does not prove present reachability. |

The application descriptor pins the control key, policy, definition, execution
manifest and schema authority. Account login and directory advertisements are
routing/enrollment inputs, never generation or author authority. Applications can
grant participants both recovery and coordinator eligibility explicitly; no
creator or native process has an implicit permanent role.

Every grant states `reader`, `writer`, `coordinator`, `recovery`,
`administrator` and `dataRole` explicitly. `participantGrant(publicKey, options)`
validates those fields without inferring one power from another. The named
`controlParticipantGrant(publicKey)` is an explicit host control role: recovery
and administration, with no reader, writer, coordinator or data membership rights.

Session command and query definitions share schemas and an explicit semantic
version. Their definition digest does not hash JavaScript `prepare` or `read`
callbacks. These definitions help callers construct valid programs; they do not
replace the writer grant or prevent an authorized writer from submitting a raw
program. Command names, versions and payload claims cannot grant private-tool
rights. Privileged handlers must check authenticated authorship and current
application policy independently.

## Selection and ancestry

A signed transition binds an exact transition identity, expected selected
generation, requester, candidate, control revision, reason and complete adopted
prefix. It also requires `controlIntentDigest`, computed with
`controlIntentDigest(control)` over the exact unsigned referenced `ControlRevision`.
That commitment includes the grants and every role, epoch, key commitment,
recovery floor and control-chain fields. It is required even when the transition
references the unchanged current control. The later signed control record has its
own digest; a control revision number alone cannot bind the requested authority.

The signed request also requires `contextDigest: string | null`. Use `null` when
there is no external transition context. Otherwise the caller must be able to
derive the commitment to the exact supplied context, and the service consuming
that context must verify it before signing or selecting. For example, Tendriller
commits supplied device-to-account bindings through its canonical
`peerAccountBindingsContext` helper and `peerDigest`. Portable control verification
authenticates the commitment, not unavailable host account data. A service must
not append grants or alter account bindings after a device signs its intent; an
explicit host-authored transition prepares the full payload before signing.

Compare-and-swap selects one successor. Exact transition retries recover the same
selection even when subsequent generations exist. Reusing the identity for a
different request, control payload or context fails.

Each successor adopts an evidence prefix of the *currently selected history*.
A prefix in an inherited generation carries a chain of signed inclusion headers
connecting it to that generation's exclusion cutoff. If G2 adopts G1 through 80,
G3 can never inherit G1's positions 81–100. A valid old signature does not erase
this cutoff. `PeerAuthority` implements these checks. Native, browser and
hosted consumers must use the verified selection rather than substitute callbacks
that bypass its authority decisions.

The control verifier establishes selected evidence membership. It does not prove
that a candidate possesses original proposal bodies, keys or replayable state.
The replica verifies that availability before publishing an applied view. It
retains available excluded history for review and preserves original bytes and
operation identities in the adopted set. A recovering peer cannot expose an
applied view before it has the complete selected input. There is no automatic
branch merge or application resubmission.

## Applied replay and observed results

`PeerReplica` depends on `AppliedMaterializationRuntime`. This port exposes
replay, publication, outcomes, SQL and captured applied reads, with no final
fields, final-view selector or disabled finality methods. Its event implementation
is `createAppliedEventMaterializationRuntime`; native SQL uses
`AppliedMaterializer.open` and `createDoltLiteAppliedMaterializationRuntime`.
Live wrappers add their separate immutable final-prefix contract. An applied
engine does not allocate a final SQL reader or persist a final-prefix checkpoint.

An `AppliedResult` carries the `PeerRevision` at which its accepted or rejected
outcome was observed. Its generation and sequence identify its inclusion receipt,
not an execution position. That outcome can change when another included proposal
sorts earlier or when recovery selects different evidence. Exact application
retries preserve the original signed bytes, identity and preconditions; they
recover the current observed result rather than promise an unchanged execution
outcome. This differs from an idempotent control-transition retry, which returns
the exact previously selected generation.

SQL, effective events, outcomes and view revisions are published coherently after
replay. A captured peer view carries that observation's authority, revision, read
handle and outcomes together. An `AppliedReadHandle` pins its original immutable observation while the
current view changes. Session `changes()` invalidates projections and recovery
also emits an explicit notice. Event cursors belong to their captured revision;
consumers rebuild a projection after a revision change instead of treating such a
cursor as a final-event processing checkpoint. The session raises
`ChangedViewError` for a cursor from another revision. Its
`operations.subscribe({ operationId, author, signal })` coalesces current operation
observations and keeps running after an applied outcome.

`observedRevision` records selected ancestry that the author reviewed. It detects
excluded ancestry; it is not compare-and-swap, an execution barrier or proof that
a business assertion remains true. Put those assertions in the program. The
session's `reapply` operation creates a newly signed attempt with a new operation
identity and `reapplyOf` lineage, under current authorization and reviewed domain
preconditions. An abandoned attempt is never silently resubmitted as fresh work.

The profile has no `final()` operation, final state, closed author-time frontier
or `FinalEventSource`. Ordinary async collaboration does not need these live
contracts. SQL authorization is also a separate execution policy: choosing an
applied runtime does not remove row ownership or schema protection.

## Controls, keys and recovery floors

Controls form a signed monotonic chain, activated with a generation. Revoking a
reader requires a fresh encryption epoch and key commitment. Historical grants
remain available to verification; each command binds authorization to its
selected control context. An author timestamp cannot itself grant revoked
permissions, and retained plaintext cannot be revoked.

The native session SQL composition authenticates both `sqlPolicy: 'data-only'`
and `authorizationPolicy: 'external-membership'` in its execution manifest.
Verified controls project each non-null `dataRole` into the reserved application
collective. Each proposal executes with the membership from its exact historical
signed control; before publication, the latest selected control is reapplied.
Recovering an older application prefix therefore cannot restore removed current
data rights. Complete membership metadata is derived from the verified control
prefix, so different arrival or replay paths produce the same protected state.
Other collectives and principal identities are preserved.

Application proposals cannot rewrite this membership projection or schema.
Bootstrap schema authorization remains separately pinned by the descriptor.
The external-membership composition currently belongs to applied SQL; it is not
silently added to live materializers. Applied engines can also use the separate
`transaction-grants` policy for owned rows. Inclusion policy, SQL permissions and
finality are distinct choices rather than an implicit profile permission switch.

A recovery floor cannot regress or disappear. Introducing a new floor binds it to
the exact adopted base, and a successor must select evidence at or after that
floor. This protects inclusion membership only: it neither freezes SQL state nor
makes application outcomes irreversible. Protected SQL administration is enforced
by the separately pinned execution policy and authenticated bootstrap schema, not
by the recovery floor. Reopening established control state with `requireExisting`
refuses missing storage rather than silently creating an empty registry.

Irreversible external actions cannot be dispatched automatically on mutable applied
events. An integration for such actions needs explicit business
preconditions, effect identity, provider idempotency and reconciliation. It must
not add a finality requirement to ordinary async collaboration.

## Session ownership and retention

`@chronolog/peer-session` owns one durable signed-attempt journal per application
device. Commands created while disconnected remain saved; reconnecting retries
those exact bytes. Cancelling `operation.applied({ signal })` cancels only that
waiter. Native devices use an exclusively owned SQLite store. The browser entry
requires an owning Worker, Web Locks and OPFS, and refuses a second owner or
missing required capabilities.

`PeerReplica.ready` reflects completed selected-history materialization. A session
remains `waiting` when adopted bodies are missing, even if its generation is
verified and its coordinator is connected. Connection state cannot substitute for
a coherent readable view.

`connectApplications` is an in-process connector for embedded peers and
independent-store tests. It exchanges verified history, retained-prefix evidence
and signed live signals. Its signal policy permits current readers; the live
Chronolog composition's topic-specific writer grants are a different policy.
Signals remain disposable and never enter deterministic replay.

`connectApplicationTransport` runs the same session protocol over an authenticated
`FramedPeerConnection`. `connectApplicationWebRtc` and
`connectNativeApplicationWebRtc` compose it with the maintained RTC transport.
Reliable command/history traffic and disposable live signals use separate lanes.
The framed protocol bounds encoded frames, concurrent requests and history
transfers; its current limits are 1 MiB per frame, 16 outstanding requests, and
4,096 records / 64 MiB of encoded records per synchronization.

Synchronization requests ranges against one captured revision and its matching
authority. A peer acknowledges retention only after storing the selected inputs,
and signs the captured prefix the recipient advertised, even if the sender now
holds more history. An older ready peer may supply bodies for a newer selected
prefix without regressing that selection. This is bounded selected-prefix recovery,
not arbitrary branch merging or a way to reintroduce an excluded suffix.

`operation.shared()` waits for independently retained complete coverage. Distinct
sessions using the same storage owner do not count as distinct copies. Coverage
does not freeze an outcome or promise that the remote copy is still available.
If neither the selected coordinator nor an authorized replacement is available,
saved intent waits; there is no fallback authority or alternate local outbox.

## Qualification and remaining deployment work

The executable control cases cover exact first-use control/context commitments,
explicit independent roles, competing successors and exact retries,
independent recovery/coordinator permissions, three-generation exclusion, inherited
prefix bridges, authenticated profile/application/execution bindings, restrictive
controls and recovery floors, required key rotation on reader removal, and refusal
to recreate missing established control state. They use `MemoryPeerStore`; reopening
the same in-memory store is not a crash-durability qualification. Production use of
the registry requires an exclusively owned store with atomic durable writes.

Replica tests exercise encrypted signed attempts, contiguous inclusion evidence,
missing or altered input refusal, exact retry after a lost storage acknowledgment,
three-generation recovery, held views and coordinator-equivocation fencing.
Native SQL tests exercise actual deterministic replay, guarded schema and row
authority, historical membership versus current rights, identical protected state
across control-arrival paths, conflicts and recovery. Session tests use independently opened native
stores for saved-intent reconnect, lost replies, cancelled waiters, explicit
reapplication, close/reopen and exclusive ownership. Framed transport tests cover
authenticated peers, independent live traffic, delayed timestamp-ordered intent,
durable captured-prefix acknowledgments, empty-peer recovery and body transfer
from an older selected generation. Test fixtures use the same applied runtime
contracts as application code.

These tests do not qualify a deployed control service, Internet WebRTC routes,
real browser/native generation sessions, process termination at every storage
boundary or a global loss bound. A browser entry point and a portable package are
not evidence of those deployment properties. Consult the test results and artifact
provenance for the exact checked revision; live-profile qualification does not
automatically apply to this profile.

Recovery requires original bodies, contiguous inclusion evidence, controls, keys
and operation identities sufficient for deterministic replay. Metadata or a signed
database image alone is insufficient. The packages provide descriptor-bound schema
verification and portable packaging, not a substitute for that retained history.

Replication freshness, second-copy retention and loss estimates need declared
workloads and measured deployment runs. No operating loss bound is established by
these tests. Recovery notices distinguish known excluded
work from unknown loss; directory last-seen times cannot establish that bound.

There is no migration or backward-compatibility layer. History profiles are
authenticated and immutable; live histories are never silently reinterpreted as
peer-generation histories.
