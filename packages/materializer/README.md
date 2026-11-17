# `@chronolog/materializer`

This package defines the execution boundary used by every Chronolog application
session. The verified history owner supplies an ordered list of `ReplayProposal`
values and its current signed execution controls. A materializer validates the
original proposal bytes, executes that supplied order and exposes one coherent
revision with command outcomes, events and optional SQL queries.

The same boundary serves native and browser storage, ordinary participants and
explicit transport roles. Ordering belongs to the history owner. A materializer
does not sort a second history or infer settlement from a participant role.

## Execution and publication

`ChronologMaterializationRuntime` separates the coordinator's replay/publication
port from application reads. A replay produces a candidate revision; publication
makes that revision visible atomically. Captured views retain the exact revision
and must be released. Changed outcomes are reported with the revision that made
them visible, including removal of outcomes excluded by explicit recovery.

`ReplayProposal` preserves the original canonical proposal, its signed digest,
transaction ID and decoded transaction. Author timestamps and deterministic
entropy remain those original transaction inputs. The runtime never substitutes
ambient time or randomness.

Protected schema and collective permissions arrive as explicit verified
`PeerExecutionControls`. The SQL materializer retains their authenticated
projection across replay and refuses to erase it through an omitted control
argument. Event and SQL execution use this same runtime contract.

An optional `coordinator.publishFinal()` capability allows an explicit settlement
owner to protect a prefix. Its presence is observable; ordinary replay does not
claim it has settled history. Default application reads observe the current
applied revision. A caller requesting a final view must choose it explicitly.

## Event execution without SQL

`createEventMaterializationRuntime({ store, namespace })` executes literal durable
events through the common runtime. `store` implements the shared `BytesStore`
contract. The runtime writes immutable ordered records before an atomic durable
head selects the current history. It bounds record count and retained bytes and
verifies the complete linked history on reopen.

Duplicate operations have deterministic outcomes. A SQL step reports
`profile:sql-disabled`; the event runtime has no SQL engine dependency. Inputs
are copied before queued work begins, and returned outcomes cannot mutate the
retained history. One `eventExecutionManifest()` identifies this execution
capability independently of ordering or transport roles.

A failed storage acknowledgment may follow a successful durable write. The
runtime therefore closes its mutation/publication ports and requires reopen
from the durable head. Existing read snapshots retain their last acknowledged
coherent view. Tests cover failures before publication and lost acknowledgments
after both replay and explicit settlement.
