# Deterministic ordering and pluggable finality

Chronolog has one application ordering rule:

`(signed author timestamp, signing public key, stable proposal ID)`.

The outer feed sequence is fixed to zero in this comparator. Given the same
finalized proposals, every replica derives the same relative application order.
Relay choice, network arrival and receipt-log position are not sorting keys.
The provider can change the included set, but cannot choose an ordering rule
for that set. SQL and effective event cursors follow the same chronological
application prefix.

## Three separate decisions

1. **Validity:** the core verifies original signatures, group/profile, program,
   writer permission and encryption dependencies.
2. **Inclusion:** a provider establishes which exact records may participate.
3. **Finality:** the provider proves a closed timestamp frontier. Later first
   inclusions at or below that frontier cannot change the finalized prefix.

The core sorts the valid included proposals and applies them locally. A receipt
certificate alone proves an included set, not final application state. Missing
bodies, keys, proof predecessors or execution support block progress. A new late
proposal receives `FINALITY_TIMESTAMP_CLOSED`; an exact retry of an earlier
proposal returns its original outcome and does not enter history again.

The fixed-validator implementation supplies admission attestations and signed
cutoff/closure promises. The signed-inclusion implementation supplies certified
receipts and explicit signed author-time closures. Both use the same sorter.
The internal `coordinated` configuration discriminator names the latter proof
family; it no longer selects append-order execution.

## Provider interface and configuration

`FinalityProvider` is exported from `@chronolog/node-core/finality`. Its inputs
are opaque proof bytes (`ingestEvidence`); its output is a verified inclusion
snapshot with admission floors and closed-time boundaries. It has no comparator
or application ordering callback. `evidenceBytes` retains the proof inputs for
durable replay and peer transfer.

This extension point currently normalizes a signed-inclusion history: a pinned
history ID and signer, a retained receipt prefix and closed author-time boundaries.
It is not a generic consensus framework. A threshold or dynamically reconfigured
protocol would need its own authenticated configuration and proof rules. Merely
registering a different factory does not supply those guarantees.

`createGovernedNode` accepts a `finalityProviders` registry of asynchronous
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

- `packages/node-core/src/pluggable-finality.test.ts`: opposite receipt orders,
  timestamp ties, prefix-only pending state, late exclusion, exact retry/restart,
  future time, missing bodies and an alternate opaque proof verifier.
- `packages/node-core/src/finality.test.ts`: closure signatures, full predecessor
  history, regression, contradictory heads and forged marker input.
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
