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

The pure kernel returns immutable candidates; its host publishes them separately.
The application runtime ports also describe that publication boundary explicitly.

`ReplayProposal` is the shared input for event and SQL replay. It carries the
original canonical proposal, its digest and its stable ID. It asserts neither
admission nor finality; the caller selects which verified proposals to replay.
`ChronologReplaySuffix` carries a chronological suffix of these inputs through
the portable kernel. Application ordering uses only signed author timestamp,
signing public key and stable proposal ID. Transport sequences never enter
replay inputs or the protected SQL transaction log.

## Applied replay and live finality

`AppliedMaterializationRuntime` exposes replay, atomic publication and reads of the
currently applied revision. `AppliedApplicationSnapshot` and `AppliedReadHandle`
capture that revision's application entries and SQL together. They have no finality
fields or view selector; the runtime has no final-prefix operation. Captures remain
stable when a later publication replaces the applied state. Async consumers can
use this port without implementing or pretending to implement finality.

The live `ChronologMaterializationRuntime` wraps the same replay engine with a
separate `LiveMaterializationCoordinator` and local/final query views. Only this
composition records and enforces a proven immutable prefix. Finality is a live
consensus capability, not a property of signed proposals or timestamp ordering.

For SQL, `AppliedMaterializer.open` and
`createDoltLiteAppliedMaterializationRuntime` in `@chronolog/materializer-doltlite`
provide the applied port. Its explicit `sqlPolicy` independently selects
`authorized` schema/platform operations or `data-only` commands; the choice enters
the execution manifest's platform digest. It is not inferred from the inclusion
protocol or the presence of finality. A verified bootstrap schema has a separate
authenticated genesis identity and must match its retained bytes on reopen.

Applied SQL additionally selects an `authorizationPolicy`. `transaction-grants`
uses the existing row-ownership and grant system. `external-membership` requires
`data-only` commands and a verified `PeerExecutionControls` projection on every
replay; this choice is independently included in the execution fingerprint.
The caller verifies the signed authority chain and supplies the exact historical
control digest bound by each proposal. Replay applies that historical membership
before executing the proposal, then reapplies the latest control before publishing
the SQL view. Recovering application history cannot restore revoked current rights,
and an older control projection is rejected after a newer one has been retained.
Membership-only changes publish a new coherent applied revision even if the
proposal set is unchanged. The live factory rejects `external-membership`: final
view semantics for that composition are not implemented. Live SQL retains its
existing transaction-grant authorization and actual immutable final prefix.

## SQL-free event execution

`createAppliedEventMaterializationRuntime` implements the applied port for programs
containing literal durable events. `createEventMaterializationRuntime` supplies the
live wrapper. Both share `eventExecutionManifest()` and exactly the same comparator
and deterministic execution. A SQL step receives `profile:sql-disabled` without
loading an engine.

The applied store persists ordered proposals and a revision in one bounded atomic
value. It contains no final-prefix state. The live store additionally records its
immutable prefix atomically; reopening one composition's state as the other is an
error. SQL follows the same separation and opens no final reader or reference for
an applied runtime.

The coordinator supplies a chronological selection of already verified proposals.
A newly eligible earlier proposal can change replay order and outcomes; a proposal
that loses eligibility can leave the selection and later reenter with its original
identity. Removing an outcome emits a change with `current: null`. In the live
wrapper these changes are confined to the provisional suffix: the final prefix,
its complete proposal identities and its event IDs are immutable.
The direct materializer port trusts its caller to supply immutable proposal IDs;
the shipped node derives each ID from the canonical proposal hash. It does not
maintain a second historical identity registry for proposals outside its current
selection.
Inputs are copied before waiting for queued work, and returned outcomes cannot
mutate the runtime's retained state.

If an atomic storage write throws, it may have committed before its reply was
lost. The runtime closes its mutation and publication ports immediately. Reopen
from the authoritative stored value before continuing; retrying from the old
in-memory state could overwrite a newer durable publication or live finality
promise. Existing read
snapshots retain their last acknowledged coherent view. The regression suite
covers failures before a write and lost replies after both replay and finality
commits.
