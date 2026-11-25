# Row ownership, schema ownership and collective membership

Every SQL transaction executes as its original signing device in canonical authored-time order. Enrollment, hosting, publication and finality authority never impersonate an author or imply row or DDL permissions.

## Independent permission domains

- **Row owner**: each registered row carries `chronolog_owner`, a principal id mapped to a signing key or collective. Generated triggers enforce owner, collective-governance and explicit row/table grants on DML.
- **Collectives**: membership and governance are ordinary authenticated platform operations. `GROUP_COLLECTIVE_ID` is the genesis collective; additional collectives are created by ordinary authored operations, not an externally refreshed membership overlay. A `SetMembers`, `AcceptMembership` or `Leave` affects subsequent chronological execution, including replay and final-prefix publication. A late predecessor can revise its provisional outcome.
- **Namespace owner**: the trusted initial `rootPrincipal: Uint8Array` owns the application's `main` creation namespace. Initialization seeds only internal catalogs, the root principal and initial `group` collective; application schema is always an ordinary transaction. Reopening verifies the engine/platform manifest and trust root, never a fixed application-DDL digest.
- **Object owner**: a newly created table, view or virtual table belongs to its creating signer. Its owner has `alter`, `drop`, `index` and `trigger` rights on that object. Namespace creation rights do not authorize changing someone else's object. Row ownership, collective administration, writer status and finalizer roles confer no implicit DDL rights.

## Ordinary DDL grants

`platformOp.grantDdl({scope, grantee, operations})` is a typed program step (`op: 'grant_ddl'`). `scope` is `{kind: 'namespace', name: 'main'}` with `operations: ['create']`, or `{kind: 'object', name}` with an ordered subset of `['alter', 'drop', 'index', 'trigger']`. Only the scope owner may grant. Grants do not include delegation authority. `platformOp.revokeDdl(grantId)` (`op: 'revoke_ddl'`) permits the granting owner to revoke or the recipient to renounce. The grant id is `platformObjectId(txId, stepIndex)`.

The protected, replicated catalogs are `chronolog_ddl_namespaces`, `chronolog_ddl_objects` and `chronolog_ddl_grants`. Object rename preserves its owner and moves its grants; drop revokes those grants, so recreation does not revive them. Index/trigger create and standalone drop require rights on the **target object**, not on the index/trigger name. An authorized parent table/view drop includes its implicit index/trigger cleanup; it does not authorize unrelated standalone drops.

Before each SQL statement, trusted platform code derives a fresh internal snapshot:

```ts
{ create: boolean, alter: string[], drop: string[], index: string[], trigger: string[] }
```

The default is `create: false` and four empty lists. Both the TypeScript/WASM authorizer and Celld's native `mode: 'replicated', ddlPermissions` statement ABI enforce this snapshot. Authored SQL cannot supply it. Permissions granted or revoked earlier in the same transaction are visible to the next step. Authorization inventories are read from the current catalog; a rollbackable schema cookie is never a cache identity.

## Atomicity and safety

DDL, DML, grant/revoke, membership and emits share one savepoint and one outcome. A failure leaves no partial application schema, owner bookkeeping, grants, data or effective emits. Earlier late operations may change later SQL/DDL outcomes; no dependency sort moves schema transactions ahead of their signed time.

Reserved internal catalogs remain protected, including renames into reserved names. PK/owner-column and FK ownership invariants remain mandatory. Application triggers and invoker views execute as the original signer and can narrow business rules, never widen authority. Virtual/shadow tables retain their write restrictions: authorized virtual-table lifecycle operations may perform module-internal shadow cleanup, but explicit shadow SQL gains no privilege. Temporary/attached databases, extension loading, transaction-control SQL, writable pragmas and forbidden modules remain denied.

Captured read leases retain their original schema and data while newer publications rederive both. Subsequent local queries see the new schema or an explicit stale-query error; they do not mutate drafts or block unrelated offline authoring. Final SQL publication replays only its authenticated immutable prefix, without applying any external latest-membership overlay.

Write ownership is not confidentiality: readers see public row values. Use [sealed values](sealed-data.md) for recipient-restricted fields. See [Replicated SQL](implementation-specs/10-deterministic-sql-transactions.md) for full program semantics and [the operation-set contract](CRDT_CONTRACT.md) for authored ordering and optional finality.
