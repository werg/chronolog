# Chronolog Implementation Specifications

The active contract is
[Specification 10: Replicated SQL Transactions](10-deterministic-sql-transactions.md):
a transaction is ordinary SQLite SQL; determinism comes from a pinned engine
with per-transaction fixed inputs and a short block-list; only database state
is replicated.

The [design](../design.md) describes the rest of the system (admission,
ordering, replication, membership, materialization) and
[governance.md](../governance.md) the membership operations.

Chronolog has no released protocol or user data. Formats and APIs are edited
in place; there are no legacy decoders, compatibility profiles or migration
paths.
