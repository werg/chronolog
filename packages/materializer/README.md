# `@chronolog/materializer`

This package is the portable boundary between Chronolog coordination and a
database materialization host. It intentionally has no workerd, Node, DoltLite,
filesystem, transport, clock, or random-source dependency.

It owns:

- exact object, artifact, and immutable database reference shapes;
- canonical CBOR codecs for invocation, replay suffix, continuation, outcome,
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

The package does not define mutable publication. Reduction returns immutable
candidates; a coordinator publishes those candidates separately.

`ReplayProposal` is the shared input for event and SQL replay. It carries the
original canonical proposal, its digest and its stable ID. It asserts neither
admission nor finality; the caller selects which verified proposals to replay.
`ChronologReplaySuffix` carries a chronological suffix of these inputs through
the portable kernel. Application ordering uses only signed author timestamp,
signing public key and stable proposal ID. Transport sequences never enter
replay inputs or the protected SQL transaction log.

## SQL-free event execution

`createEventMaterializationRuntime` implements the ordinary materialization port
for groups whose programs contain only literal durable events. It persists the
ordered proposals, local revision and immutable final prefix in one bounded
atomic storage value. Duplicate operations have deterministic outcomes; a SQL
step receives `profile:sql-disabled` rather than loading an engine.

The coordinator supplies a chronological selection of already verified proposals.
A newly eligible earlier proposal can change the provisional suffix; a proposal
that loses eligibility can leave that suffix and later reenter with its original
identity. Removing a provisional outcome emits a change with `current: null`.
The final prefix, its complete proposal identities and its event IDs are immutable.
The direct materializer port trusts its caller to supply immutable proposal IDs;
the shipped node derives each ID from the canonical proposal hash. It does not
maintain a second historical identity registry for proposals outside its current
selection.
Inputs are copied before waiting for queued work, and returned outcomes cannot
mutate the runtime's retained state.

If an atomic storage write throws, it may have committed before its reply was
lost. The runtime closes its mutation and publication ports immediately. Reopen
from the authoritative stored value before continuing; retrying from the old
in-memory prefix could overwrite a newer durable finality promise. Existing read
snapshots retain their last acknowledged coherent view. The regression suite
covers failures before a write and lost replies after both replay and finality
commits.
