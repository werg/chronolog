# Deterministic ordering and pluggable finality

Chronolog has one application ordering rule:

`(signed author timestamp, signing public key, stable proposal ID)`.

The comparator accepts only those three fields. Given the same finalized
proposals, every replica derives the same relative application order.
Relay choice, network arrival and receipt-log position are not sorting keys.
The provider can change the included set, but cannot choose an ordering rule
for that set. SQL and effective event cursors follow the same chronological
application prefix.

Chronological ordering does not require finality. The current live collaboration
policy adds an irrevocable prefix and the final-only readers and effects that
depend on it. An asynchronous branching and merging policy would reuse signed
operations, timestamp ordering and replay, and would have no finality. No such
policy is implemented here, and it would not implement a disabled live frontier.

## Three separate decisions in live collaboration

1. **Validity:** the core verifies original signatures, group/profile, program,
   writer permission and encryption dependencies.
2. **Inclusion:** a provider establishes which exact records may participate.
3. **Finality:** the provider proves a closed timestamp frontier. Later first
   inclusions at or below that frontier cannot change the finalized prefix.

The core sorts the valid included proposals and applies them locally. A receipt
certificate alone proves an included set, not final application state. Missing
bodies, keys, proof predecessors or execution support block progress. A proposal
proved unable to enter a closed history receives a final rejection; an exact
retry of an earlier proposal returns its original outcome and does not enter
history again. A timestamp below a validator watermark alone is not enough to
reject a partially admitted proposal.

The fixed-validator implementation supplies admission attestations and signed
cutoff/closure promises. The signed-inclusion implementation supplies certified
receipts and explicit signed author-time closures. Both use the same sorter.
The internal `coordinated` configuration discriminator names the latter proof
family; it no longer selects append-order execution.

## A shared live frontier, with separate proof adapters

`LiveFinalityFrontier` is the common result consumed by live execution. Its
`provenThroughMs` records the proof's raw time boundary; `closedThroughMs` also
accounts for every unresolved earlier admission. A blocker at timestamp T caps
that usable boundary at T - 1 (or no boundary when T is zero). `blockers` retain
the proposal and available proof IDs; `exclusions` carry each proved impossible
proposal and its precise rejection reason. Final application publication additionally waits
for the corresponding proposal bodies, keys and replay to complete. This is a
live consensus capability, independent of the common operation and ordering
primitives.

For fixed validators, a blocking set of cutoffs only excludes entirely unseen
proposals. A known proposal with a partial quorum can still gain delayed votes
from other validators. The adapter therefore considers each pending proposal's
own policy and revision, including proposals with no local votes, and waits
until it is admitted or its remaining eligible voters cannot form a quorum.
The raw frontier must also be safe for every policy permitted by the history,
including an easier policy than the latest applied proposal uses.

`MembershipResolver.admissionScopes()` supplies the complete activated
revision history, including every permitted policy and each revision's
authenticated exclusive author-time floor. Closed revisions remain in this
enumeration. Discovering policies only from locally seen proposals or the latest
revision cannot establish completeness. An adapter unable to establish that
guarantee must leave the scope enumeration unavailable, keeping application
finality pending.

Each still-open scope is bounded by the least advanced policy it permits. Its
authenticated activation floor is safe even before that scope has a usable
cutoff; advancing beyond the floor requires every permitted policy's cutoff.
The group takes the minimum across all still-open scopes. Closing one revision
cannot lift another revision's bound. Only when every scope is verifiably closed
can the maximum closed boundary represent a history with no remaining admission
scope.

A cutoff becomes usable only after both transport replication and the current
admission index have consumed its complete authenticated feed prefix. Filling a
gap upgrades this local proof monotonically; reopening a durable snapshot still
requires the current admission index to catch up. Complete governance revision
closures supply the same admission-completeness evidence through their verified
feed prefixes. The execution core consumes the resulting frontier without a
separate governance-finality shortcut.

A custom peer membership resolver supplies this complete `admissionScopes()`
history. A verified revision closure does not substitute for missing scope
completeness. With complete scopes, closure evidence can establish progress
without heartbeats, bounded by the authenticated floors of still-open scopes
and requiring indexed admission prefixes. Each pending proposal's own policy
and verified votes determine whether it can still be admitted.

## Live inclusion verifier interface and configuration

`LiveInclusionFinalityProvider` is exported from `@chronolog/node-core/finality`.
Its inputs are opaque proof bytes (`ingestEvidence`); its `LiveInclusionSnapshot`
output contains verified receipts, admission floors and closed-time boundaries. It has no comparator
or application ordering callback. `evidenceBytes` retains the proof inputs for
durable replay and peer transfer.

This extension point currently normalizes a signed-inclusion history: a pinned
history ID and signer, a retained receipt prefix and closed author-time boundaries.
It is not a generic consensus framework. A threshold or dynamically reconfigured
protocol would need its own authenticated configuration and proof rules. Merely
registering a different factory does not supply those guarantees.

`createGovernedNode` accepts a `liveInclusionProviders` registry of asynchronous
factories. The registry key is the `providerId` authenticated by signed genesis.
`providerParameters` are bounded opaque configuration bytes, also authenticated.
The built-in IDs are `peer-validators-v1` and `signed-inclusion-v2`; a custom
inclusion verifier is resolved through the registry. An unknown ID or a returned
configuration that differs from genesis fails explicitly. Selecting a transport
does not select a verifier, and a host response cannot silently switch providers.

A custom verifier must establish immutable inclusion identity, a complete proof
prefix and monotone closure promises. Its normalized receipt enumeration is
used for evidence/dependency bookkeeping only. The application core still checks
validity and author time and rejects a regression in applied finality. An
implementation which invents proof or equivocates violates the selected trust
model; an interface cannot turn such a provider into a fault-tolerant protocol.

The provider is pinned for a continuing group. Automatic provider replacement,
validator-set reconfiguration and authority failover are not introduced here.
This is a pre-release format change; there is no old-prefix-only finality fallback.

## Retained evidence and application publication

Evidence storage is an untrusted, content-addressed input log. It can contain
unrelated or malformed peer bytes; only the selected verifier can advance trusted
inclusion and closure state. When an evidence transport is configured, direct
node ingestion first durably retains the raw input, then asks the provider to
verify and retain its trusted state. Failed raw retention therefore cannot
advance the provider's frontier. A manually driven node without an evidence
transport relies on the provider's own durable store. A provider whose durable
write has an uncertain outcome must fence further progress until reopen.

The transport exposes two bounded streams:

- `evidenceHistory(signal?)` captures the retained head and yields
  `EvidenceBatch` values through that finite position.
- `subscribeEvidenceBatches(signal?)` yields retained evidence and then waits for
  later commits. It does not wait to fill a batch before delivering live evidence.

These streams partition a captured retained prefix into bounded batches; they
need not preserve the original network page or write-call boundaries.

`putEvidenceBatch(bytes)` publishes its local storage changes atomically, after
all immutable objects and the manifest or database transaction are durable. A
batch contains at most 64 inputs and 64 MiB of input bytes. The singleton
`putEvidence(bytes)` uses the same path. A received network page advances its
delivery cursor only after the batch commit; an interrupted attempt can retry
the same exact bytes. An unrelated feed notification cannot expose part of an
in-flight batch.

The node verifies each retained proof, ignores individually invalid shared
inputs, and reconciles the application once per batch. Unexpected verification
or storage failure in a shared batch stops the consumer and fences further
application progress with `NODE_EVIDENCE_REOPEN_REQUIRED`. The last coherent
view remains readable; reopen replays the retained batch without skipping its
unfinished tail. A fully verified batch whose materialization is blocked by
missing proposal bodies or keys uses the existing derived-view retry path.
Startup, explicit idle barriers and the live consumer use this same bounded path,
so a new replica
can replay many historical closures without reopening and publishing the SQL
readers after each one. Direct `ingestFinalityEvidence(bytes)` delegates to a
single-element `ingestFinalityEvidenceBatch(bytes)` and retains its immediate
reconciliation behavior.

These are local storage and publication boundaries. They do not combine
application programs into a transaction, make invalid proof valid, change
ordering, or confer authority on the transmitting peer. A published view remains
one coherent application prefix under the original proof rules.

## Fixed-validator closure and partial admission

A validator's signed heartbeat promises that its subsequent feed will contain
no admission at or below its cutoff. The promise becomes usable only after this
replica has consumed the complete authenticated feed prefix through that
heartbeat. Having the bytes in a transport cache is insufficient: a preceding
vote may not have reached the admission index yet. Filling a feed gap completes
an existing heartbeat without requiring the validator to sign another one.
Unprocessed admission records, missing signed proposal bodies and unresolved
decryption dependencies keep affected application history provisional.

For a plain `k`-of-`n` policy, cutoffs from `n-k+1` validators intersect every
possible admission proof. The corresponding raw watermark establishes that
every earlier possible proof has some evidence in those complete feeds. It
does **not** establish that every proof is already complete or impossible.

For example, take a two-of-three policy with validators A, B and C. An earlier
proposal P has A's vote; a later proposal Q has A's and B's votes. A and B then
close time past both proposals. C can still legitimately provide P's second
vote. Freezing Q at that point would let P arrive before an immutable prefix.
Chronolog keeps Q provisional until P is admitted or proved impossible.

For each known pending proposal, the core combines its existing authenticated
votes with every policy validator whose complete feed has not closed that
proposal's signed timestamp. If the exact pinned policy can still admit from
that set, the proposal remains a blocker for any later application prefix.
It does not block an earlier prefix. Unknown proposal bodies referenced by
admission records also block finality until their meaning can be verified.

When no possible remaining evidence can admit a proposal, its persisted
candidate state becomes `excluded`. Applications observe `final` with outcome
`rejected`; no synthetic transaction is inserted into SQL or effective events.
The rejection is `FINALITY_TIMESTAMP_CLOSED` when time or revision closure
caused the impossibility, or `ADMISSION_IMPOSSIBLE` when the pinned policy and
grants could never admit it even with every validator still open. A proposal
with sufficient existing votes is not rejected merely because its timestamp
is now below a cutoff. These decisions and the final application prefix survive
restart and exact retry.

### Policy scope and custom resolvers

Every verified membership revision has one active validator grant per signing
key, with one authorized replication feed. A key contributes one vote;
additional grant IDs or repeated attestations do not create independent voters.
Genesis and successor reduction reject overlapping grants with `SCHEMA_INVALID`
before the new snapshot can affect admission or watermark calculation. Local
governance authoring validates that transition before retaining or publishing
the operation, and received invalid controls do not stop subsequent valid ones.
At the capability layer, revocation and replacement are one atomic transition,
so historical snapshots retain the old feed without authorizing it in the new
revision. The fixed-finality profiles still pin their validator set; this
invariant does not introduce live validator reconfiguration.

`MembershipResolver.watermarkPolicy({ groupId, membershipRevision,
validationPolicy })` describes the requested policy's complete validator
universe and threshold. The exhaustive `admissionScopes({ groupId })` contract
also covers activated revisions with no locally observed application proposal.
The global frontier is constrained by every policy in every still-open scope:
considering only Q's policy could miss an unknown earlier P that uses a lower
threshold. The capability resolver enumerates the authenticated activation
history. Static membership supplies one scope and one threshold; a separate
configurable watermark threshold would permit unsound closure. Omitting the
complete scope enumeration keeps provisional replay available without claiming
heartbeat finality.

Actual admission and potential admission still use each proposal's exact
policy, version, signing keys, grants and timestamp floors. A custom
`selectAdmission` implementation can supply
`canStillAdmit(context, { attestations, openValidatorIds })`. Returning `false`
is a proof obligation: no subset or future combination of legitimate evidence
from the open validators can satisfy that pinned policy. Returning `true` may
be conservative. Without that evaluator, a custom selector's undecided
proposals remain blockers even after a raw watermark advances. This preserves
safety but can delay finality indefinitely; custom policies must implement the
evaluator for automatic exclusion and progress.

Revision closure additionally requires every predecessor validator's complete
admission feed. The core waits for the referenced signed proposal bodies and
consumed decisions before closing that revision's application results. A new
governance head does not turn a partial old proof into a final result.

`ClosedAdmissionRevision` names both the closed revision and its authenticated
`nextMembershipRevision`. The successor authorizes only author timestamps
strictly after `closedThroughMs`; the governed membership resolver enforces this
against the timestamp-effective snapshot. A local author-clock hint alone is
insufficient. The evaluator follows the verified activation chain from genesis
and uses each boundary only as its successor's lower bound. Every still-open
revision contributes its own safe boundary, and the global frontier is their
minimum. A closed revision cannot lift an unrelated open revision. Conversely,
fully consumed old work can become final at the activation boundary before the
successor publishes its first heartbeat. Custom governance and membership
adapters must uphold the same complete revision/activation contract.

`node.watermark()` resolves the current operational policy, including in an
empty group; it is raw policy evidence. `node.liveFinality()` reports the usable
history-wide proof. Newly authored timestamps advance beyond observed verified
history cutoffs and applied history even if the local wall clock moves backward.
Applications do not calculate their own timestamp offsets.

The fixed-validator model trusts its selected validators to honor their signed
cutoff and revision-closure promises and retain their feed continuity. It is
not a Byzantine consensus protocol: detecting a contradictory promise or feed
fork cannot make an already dishonest signer truthful. Transport identity,
authenticated signatures, consumed prefixes and exact policy evaluation are
all necessary parts of this trust model; arrival order is not evidence of
finality.

## Durable signed-inclusion closures

The native service retains exact descriptors and detached bodies. Its receipt
log is an availability/inclusion structure. A separate signed closure record
commits the exact preceding included head and an author-time cutoff. It is
appended durably before the ordinary prefix certificate is released.

All closures travel with the retained history. A fresh replica reconstructs the
cutoff that existed before each proposal's first inclusion. Keeping only the
latest cutoff would be unsafe: it could erase evidence that a backdated proposal
arrived after an earlier closure. Missing prefixes block; authentic conflicting
or regressing promises fail continuity verification. Unauthenticated marker-like
writer bytes cannot create a closure.

The retained verifier owns an immutable, authenticated prefix. A certificate
selecting an extension must agree with that exact predecessor before its new
suffix is checked. Newly added closures are verified once against the retained
admission floors, first covering closures and control projection; an arbitrary
caller-supplied snapshot cannot serve as a trusted baseline. The extension stays
staged until its durable store write succeeds. A failed storage acknowledgment
fences further ingestion until the verifier is reopened: the write may already
have committed, and a stale in-memory prefix must not overwrite that retained
proof. Reopening and the public `evaluateFinalitySnapshot()` still verify the
supplied history from genesis.
All proof bytes remain available for replay and peer transfer.

Closures can advance during an idle period. Future-dated included proposals stay
pending until the closed frontier covers their author time; only then is their
membership eligibility final. The signed genesis clock policy bounds this wait:
the maximum allowed timestamp is the proposal's first covering cutoff plus
`maxFutureSkewMs + cutoffLagMs`. Beyond that bound, `FINALITY_TIMESTAMP_FUTURE`
is a final rejection without waiting for the impossible timestamp. The exact
bound is accepted. `NativeFinalityService.open` and `withTendrillerFinality` require
a verified enrollment descriptor and derive timing directly from its signed clock
policy. Governed validators do the same. There is no separate local override for
the cutoff lag, skew allowance or heartbeat interval.

Raw `ChronologNode` embeddings without governed construction must supply
`validator.cutoffLagMs` explicitly. Omitting `heartbeatIntervalMs` means the
embedding advances the validator with `publishHeartbeat()`; omitting
`maxFutureSkewMs` uses a thirty-second allowance. These low-level choices do not
override any signed group policy.

`DEFAULT_LIVE_CLOCK_POLICY` supplies a one-second cutoff lag, one-second
heartbeat interval and thirty-second future-clock allowance. Native bootstrap
and portable Tendriller membership share these defaults.
The values become part of a new group's signed genesis; an existing group's
verified policy takes precedence over process defaults. The short tick keeps
healthy live collaboration moving without requiring another user operation.
It is not a settlement deadline: missing proof, history or keys still blocks
finality, and late first inclusion behind closed time still rejects. Deployments
that need a wider inclusion window choose it explicitly when creating the group.

The service chooses a cutoff using its clock and signed lag, independently
of encrypted application contents. After all included records' possible time
windows have closed, idle ticks add no markers. New receipts restart closure
progress. Thus an empty or quiescent group does not consume its retained-history
quota indefinitely. The service needs neither decryption nor SQL sorting to
make these promises. Retained data still has the existing finite quota; history
pruning and compaction are not introduced here. The native service separately
budgets retained descriptor/closure bytes and detached application bodies, with
durable body reservations surviving lost replies and interrupted appends.

The hosted opaque log offers conditional append against an expected head, so a
concurrent writer cannot slip between a closure's signed head and its append.
Native appends and closure publication share a durable-owner lock. Persistent
volume continuity remains required; losing a provider pauses new finality and
does not authorize silently replacing its history.

## Membership is ledger data

Membership grants/revocations (`capability`) and key rotations (`epoch-manifest`)
are signed inline record kinds in the same ledger as application candidates.
They are privileged control events, not ordinary application `emit` topics.
Changing a topic name cannot grant a user membership administration rights.

Control events follow their signed predecessor/revision chains, independently
of receipt order. Their activation is a closed author-time boundary; multiple
causally successive revisions may share a boundary. A later-arriving predecessor
cannot retroactively move activation behind an already established boundary.
Application authorization uses its signed timestamp and exact grant, never a
receipt position. Old final results survive later revocation and key rotation.

Multiple encryptions of the same signed proposal resolve in the first closure
that can decide that proposal. A valid envelope takes precedence over obsolete
wrapping within that same closed set; stable record identity breaks any remaining
tie. Subsequent inclusion cannot replace an earlier final result. This rule is
the same for incremental delivery and a fresh replica replaying all proofs.

Thin administrators can obtain and verify these controls without application
bodies. Epoch issuance must be included with its dependencies in the candidate's
first covered inclusion checkpoint; later issuance cannot revive an already
excluded descriptor. A known issued key that this reader has not received is
unavailable input, not an invented application rejection. Initial epoch zero
bootstraps genesis-authorized history; later rotations apply after their closed
boundary. Application replay waits for required bodies and keys independently
of control discovery.

## Regression evidence

- `packages/capabilities/src/reducer.test.ts` and `capabilities.test.ts`, with
  `packages/node-core/src/governance.test.ts`: one active validator grant per
  signing key, deterministic distinct-key votes, historical feed binding,
  rejected local preparations and continued replay after invalid controls.
- `packages/node-core/src/pluggable-finality.test.ts`: opposite receipt orders,
  timestamp ties, prefix-only pending state, late exclusion, exact retry/restart,
  future time, missing bodies and an alternate opaque proof verifier.
- `packages/node-core/src/peer-finality-safety.test.ts`: partial validator votes,
  legitimate late admission and replay, complete consumed feeds, gap recovery,
  missing bodies, custom policy blockers, durable exclusion and restart, and
  author clocks in an empty group with a verified cutoff.
- `packages/control-store/src/control-store.test.ts` and
  `packages/node-core/src/live-finality.test.ts`: delayed partial-quorum votes,
  policy-wide frontier bounds, closed-revision exclusions and feed-gap recovery.
- `packages/node-core/src/finality.test.ts`: closure signatures, full predecessor
  history, regression, contradictory heads, forged marker input, linear closure
  verification on retained-prefix extension and retry after failed persistence.
- `packages/node-core/src/governance-activation.test.ts` and
  `canonical-epoch.integration.test.ts`: causal membership activation, cutoff
  authorization and immutable epoch dependency eligibility.
- Native authority, membership HTTP and public Tendriller adapter tests cover
  durable publication, idle progress, conditional append and restart.

Earlier qualification reports describing canonical receipt-order execution are
historical results for that earlier architecture. They do not certify this change.

## Compact participant evidence

The signed-inclusion-v2 closure also commits the complete finalized control
projection. Full peers recompute it from the original ledger; participant
administrators and newly enrolled devices verify compact control pages without
receiving application descriptors. See [compact membership proofs](membership-control-proofs.md)
for the wire, cursor, trust, and recovery contract.
