# Row ownership and collective membership

Every SQL command executes as its original signing device. Coordinating or administering a generation never grants authority to impersonate an author or edit another participant's rows.

## Authority model

- **Collective owner**: `APPLICATION_COLLECTIVE_ID` owns shared application-wide tables. Membership is projected from each participant's signed `dataRole` (`member` | `admin` | `null`).
- **Control vs. data**: `coordinator`, `recovery`, and `administrator` grants confer no SQL `dataRole`. A control-only host has no SQL membership.
- **Monotonic membership**: Replay executes historical programs under their historical control revision, then reapplies the latest controls before publishing the view. Data recovery cannot restore revoked membership.
- **Fixed schema**: Initial SQL schema is signed and pinned in the application descriptor. Ordinary commands cannot run DDL or alter platform tables.

## Enforcement

- Platform triggers maintain row ownership columns and enforce author/collective write permissions.
- Application triggers and `chronolog_assert` may narrow business rules, never widen grants.
- Every accepted program commits SQL writes and emitted events atomically; rejected programs commit neither.
- Write ownership is not confidentiality: any authorized reader sees public row values. Use [sealed values](sealed-data.md) for recipient-restricted fields.

See [Deterministic SQL](implementation-specs/10-deterministic-sql-transactions.md) for full program semantics.
