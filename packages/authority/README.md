# Chronolog authority

Portable signed application authority, independent code-publication authorization,
and optional author-time finality evidence. This package contains no application
SQL engine, native transport, operation-ordering service or application database.

Public entries are the package root, `/control`, `/metadata`, `/participant`,
`/publication` and `/finality`. The archive carries standalone modules,
self-contained declarations and source/byte provenance.

## Separate authorities

- Signed descriptors establish application identity, execution semantics, initial
  trust roots and an explicit finality policy—not an immutable application schema.
- Signed membership certificates establish cryptographic participation and epoch
  key commitments. They do not overwrite SQL permissions or collective membership.
- Publication authority is independent: a publisher can release the signed UI
  before the first data browser exists, without obtaining data keys.
- Enrollment proofs bind the application, device key, challenge, epoch and key
  commitment. Raw private signing and epoch keys do not belong in published assets.

`createAuthorityProvider` accepts a caller-owned byte store and opens cached
verified authority and keys locally. The caller must authenticate the initial
trust root through its configured service/account or explicit out-of-band policy;
a self-consistent signature alone does not identify the intended application.
Later bundles remain pinned to that root. Additional devices require explicit
recipient-authenticated key provisioning.

Application data is an authenticated operation-set CRDT, ordered only by signed
author timestamp, author public key and stable proposal ID. Ordinary permissioned
DDL, DML and application permission changes belong to authored transactions.
These authority records are not an alternative operation journal or SQL overlay.

## Optional finality

`none` is the ordinary offline-first default. Supported signed-frontier and
fixed-validator policies prove inclusion and closed author time, never operation
order. Verify the complete authenticated membership history and required scopes;
missing dependencies are pending, not fabricated final results. Explain trust,
clock and retention assumptions explicitly. Genuinely offline intent first
presented behind a sealed frontier can be excluded; preserve that original intent
without silent retimestamping.

See the [authored operation-set contract](https://github.com/werg/chronolog-db/blob/master/docs/CRDT_CONTRACT.md)
and the exact archive's `provenance.json`. Diagnostic dirty archives are not
clean-source release qualification.
