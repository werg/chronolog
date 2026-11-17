# Peer generations: selected history with tolerant recovery

Status: the portable signed control foundation is implemented and has eight
control-model tests. Application execution, peer replication, recovery of applied
views, and native/browser/hosted runtime composition remain future work. This
package does not change the default live collaboration profile.

The authenticated profile is `peer-generation-v1`, with the bounded
`eligible-members-v1` authority policy. It has no concept of finality. It is
separate from the live profile's chronological inclusion finality.

## Inclusion and application order

A signed generation delegates inclusion to one replaceable peer. The coordinator's
receipt sequence authenticates a chain of included proposal references; generation
selection chooses which receipt prefixes belong to the history. That sequence is
an evidence position, not an application execution order.

Application replay must use the shared Chronolog comparator: the original signed
author timestamp, signing public key, then stable proposal ID. Selecting a receipt
prefix supplies a proposal set to that comparator. A later receipt can include an
earlier timestamp, so it can change application order and outcomes even within the
same selected generation. Neither a receipt position nor a recovery floor closes
author time or establishes an immutable application prefix.

The implemented control participant retains signed descriptors, monotonic controls
and generation selections, and atomically chooses successors. It verifies prefix
proofs and delegated inclusion headers without application bodies or SQL. It does
not authenticate or execute encrypted application proposals. A future runtime must
verify their original authorship, authorization and execution manifest before
deterministic replay; the coordinator cannot supply trusted execution results.

The control model trusts the control service not to equivocate and assumes one
exclusive durable owner of its store. Its compare-and-swap does not implement
Byzantine consensus or distributed storage consensus. Cached delegations have no
heartbeat renewal requirement. Detecting conflicting coordinator receipts and
handling an isolated old coordinator belong to the future replication runtime.

## Separate authority concerns

| Concern | Contract |
| --- | --- |
| Authorship and authorization | Reader/writer grants identify permitted signers. Application proposal verification and SQL authorization still require runtime implementation. |
| Inclusion | A signed generation delegates receipt sequencing to one eligible reader. This grants no author or SQL administrator impersonation rights and does not change the application comparator. |
| Recovery | The requester needs explicit recovery permission; the candidate separately needs coordinator eligibility. A stored replica or writer grant alone is insufficient. |
| Control changes | An authorized administrator can request a signed control revision through generation selection. Schema authority is pinned separately. |
| Retention | A future retained-prefix acknowledgment would report stored evidence. It would grant no authority and provide no finality. |

The application descriptor pins the control key, policy, definition, execution
manifest and schema authority. Account login and directory advertisements are
routing/enrollment inputs, never generation or author authority. Applications can
grant participants both recovery and coordinator eligibility explicitly; no
creator or native process has an implicit permanent role.

## Selection and ancestry

A signed transition binds an exact transition identity, expected selected
generation, requester, candidate, control revision, reason and complete adopted
prefix. Compare-and-swap selects one successor. Exact transition retries recover
the same selection even when subsequent generations exist. Reusing the identity
for a different request fails.

Each successor adopts an evidence prefix of the *currently selected history*.
A prefix in an inherited generation carries a chain of signed inclusion headers
connecting it to that generation's exclusion cutoff. If G2 adopts G1 through 80,
G3 can never inherit G1's positions 81–100. A valid old signature does not erase
this cutoff. `PeerAuthority` implements these checks. Future native, browser and
hosted consumers must use the verified selection rather than substitute callbacks
that bypass its authority decisions.

The control verifier establishes selected evidence membership. It does not prove
that a candidate possesses original proposal bodies, keys or replayable state.
Recovery runtime work must verify that availability before publishing an applied
view, retain available excluded history for review, and preserve original bytes and
operation identities in the adopted set. There is no implemented automatic branch
merge or application resubmission.

## Application results: requirements for future composition

This package exports implemented control, schema and store primitives. It does not
export a replica interface, an application result lifecycle, or a materialization
runtime. A future async composition must not require the live runtime's final-view
fields, `final()` operation or `FinalEventSource`; this profile has no finality.

An applied result must identify the view in which a proposal was accepted or
rejected. That result can change when another included proposal sorts earlier or
when recovery selects different evidence. Exact application retries must preserve
the original signed bytes, identity and guards; they cannot promise an unchanged
execution result. This differs from the implemented idempotent control-transition
retry, which returns the exact previously selected generation.

SQL, effective events, outcomes and view revisions must be published together after
replay. A changed view needs an explicit invalidation or reset. Retaining an
inherited receipt prefix preserves proposal membership, not an execution barrier
or the truth of a previously observed business assertion. Deliberate reapplication
would require newly signed intent, its relationship to the old intent, current
authorization and reviewed domain guards. These are runtime requirements, not
claims about implemented APIs.

## Controls, keys and recovery floors

Controls form a signed monotonic chain, activated with a generation. Revoking a
reader requires a fresh encryption epoch and key commitment. Historical grants
remain available to verification; a future command runtime must bind authorization
to the selected control context. An author timestamp cannot itself grant revoked
permissions, and retained plaintext cannot be revoked.

A recovery floor cannot regress or disappear. Introducing a new floor binds it to
the exact adopted base, and a successor must select evidence at or after that
floor. This protects inclusion membership only: it neither freezes SQL state nor
makes application outcomes irreversible. The control tests do not establish
protected SQL administration; that requires a separately implemented authorization
and execution boundary. Reopening established control state with `requireExisting`
refuses missing storage rather than silently creating an empty registry.

Irreversible external actions cannot be dispatched automatically on mutable applied
events. Any future integration for such actions needs explicit business
preconditions, effect identity, provider idempotency and reconciliation. It must
not add a finality requirement to ordinary async collaboration.

## Qualification and remaining runtime work

The eight executable control cases cover competing successors and exact retries,
independent recovery/coordinator permissions, three-generation exclusion, inherited
prefix bridges, authenticated profile/application/execution bindings, restrictive
controls and recovery floors, required key rotation on reader removal, and refusal
to recreate missing established control state. They use `MemoryPeerStore`; reopening
the same in-memory store is not a crash-durability qualification. Production use of
the registry requires an exclusively owned store with atomic durable writes.

The package also implements descriptor-bound schema signing and verification and
provides a portable control-artifact packaging script. It does not yet qualify
encrypted application attempts, actual SQL/events replay, network replication,
host-blocked collaboration, recovery of incomplete bodies, independently reopened
durable stores, or installed native/browser/hosted application consumers.

A future runtime must retain sufficient original bodies, contiguous inclusion
evidence, controls, keys and operation identity for deterministic replay. Metadata
or a signed database image alone is insufficient. If both the control service and
selected coordinator are unavailable, locally saved intent must await an authorized
selection or resumed inclusion; this is a requirement to implement and test.

Replication freshness, second-copy retention and loss estimates need declared
workloads and measured deployment runs. No operating loss bound is established by
these control tests. Future recovery reports should distinguish known excluded
work from unknown loss; directory last-seen times cannot establish that bound.

There is no migration or backward-compatibility layer. History profiles are
authenticated and immutable; live histories are never silently reinterpreted as
peer-generation histories.
