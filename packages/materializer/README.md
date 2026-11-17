# `@chronolog/materializer`

This package is the portable boundary between Chronolog coordination and a
database materialization host. It intentionally has no workerd, Node, DoltLite,
filesystem, transport, clock, or random-source dependency.

It owns:

- exact object, artifact, and immutable database reference shapes;
- canonical CBOR codecs for invocation, admitted suffix, continuation, outcome,
  differential observation, and self-contained differential fixture values;
- resolution through an exact-reference-only object reader;
- an explicit pure context in which logical time and caller entropy are null in
  version 1; and
- a backend-neutral kernel and differential harness usable by both Node and
  workerd implementations.

Chronolog transaction timestamps and nonce-derived entropy remain inside each
signed transaction. A materializer host must not substitute ambient time or
randomness. The existing DoltLite implementation exposes a temporary oracle
adapter in `@chronolog/materializer-doltlite`; its output projector is injected
because only a CAS/export host can assign generic immutable output refs.

## Published application views

The runtime separates reduction, publication and querying. A reducer produces
immutable candidates; its coordinator publishes them before the query service
exposes their outcomes. `queries.captureApplication({ view: 'local' | 'final' })`
returns detached proposal bytes, outcomes and revision metadata from one published
view without leasing SQL. `captureRead()` supplies that same snapshot together
with its pinned SQL lease. Node event snapshots therefore use the exact proposal
inputs and outcomes that produced the captured SQL revision. An admitted proposal
waiting for materialization is absent from both SQL and effective events.

## SQL-free event execution

`createEventMaterializationRuntime` implements the ordinary materialization port
for groups whose programs contain only literal durable events. It persists the
ordered proposals, local revision and immutable final prefix in one bounded
atomic storage value. Duplicate operations have deterministic outcomes; a SQL
step receives `profile:sql-disabled` rather than loading an engine.
Finality publishes a monotonic prefix of the applied order; it does not expose
a control-store order before replay has finished.

The node's admitted set only grows. It currently materializes admitted proposals;
`provisional()` means that executed ordering or outcome may still change before
finality, not that the node exposes an unadmitted local proposal.

The lower-level materialization port accepts a chronological selection of verified
proposals and can replace its unfinalized suffix. A caller with an explicit preview
selection policy can remove an unadmitted preview and redo the remaining programs.
Removal reports an outcome change with `current: null`; it is not a new rejection.
Inputs that remain selected retain their exact identity. Finalized identities,
outcomes and event IDs cannot change, and all selections use the same signed
timestamp comparator. The direct port trusts its caller to supply immutable
proposal IDs; the shipped node derives each ID from the canonical proposal hash.
The runtime does not maintain a second historical identity registry for proposals
outside its current selection. Inputs are copied before queued work, and returned
outcomes cannot mutate retained state. The runtime never makes admission or
authorization policy.

If an atomic storage write throws, it may have committed before its reply was
lost. The runtime closes its mutation and publication ports immediately. Reopen
from the authoritative stored value before continuing; retrying from the old
in-memory prefix could overwrite a newer durable finality promise. Existing read
snapshots retain their last acknowledged coherent view. The regression suite
covers failures before a write and lost replies after both admission and finality
commits.

## Proposal identity

An admitted transaction contains only its stable proposal ID, signed candidate
bytes, candidate digest and decoded core. Transport feed positions belong to
replication and proof verification. The v2 admitted-suffix codec stores each
transaction as `[proposalId, candidateDigest, canonicalCandidate]` and rejects
obsolete versions and tuples. The event store, control index, SQL execution
manifest and materialized-log evidence likewise use the new format directly.
