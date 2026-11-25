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
- Enrollment proofs bind the application, device signing key, key-wrap key and host
  challenge. Raw private signing, wrap and epoch keys do not belong in published assets.

## Admission

The creator signs the descriptor (`authorityPublicKey === rootPrincipal`) and genesis
membership. Every membership revision carries an `AdmissionPolicy`
(`mode: 'attested' | 'strict'`, the pinned host attestation key, the authorized host
account principals and the grant for owner devices), the `invites` recorded by
administrators, and `admitted` evidence for members it adds. A host attestation
(`signHostAttestation`) states that an authenticated account proved a device or agent
key for one page; it is evidence, never membership. `verifyAuthorityBundle` accepts:

- any change signed by the creator key or a prior administrator (`approved` admissions
  still carry a valid attestation); and
- from any other reader, only appended members carrying `attested` evidence (an
  authorized account, attested mode, exactly the policy grant) or `invited` evidence
  (a recorded unrevoked invite whose email binding, expiry, role grant and redemption
  capacity hold), with policy, invites, epoch and existing members unchanged.

Attestation freshness is checked deterministically: the revision's signed activation
floor lies within the attestation window, and nonces are never reused in a chain. A
host that is not a member cannot sign membership; at most it can attest a key that an
online member then admits visibly and an administrator can revoke.

`createAuthorityProvider` accepts a caller-owned byte store and opens cached
verified authority and keys locally. The caller must authenticate the initial
trust root through its configured service/account or explicit out-of-band policy;
a self-consistent signature alone does not identify the intended application.
Later bundles remain pinned to that root. Additional devices receive keys only from
an existing member, wrapped to the wrap key recorded in their signed membership grant.

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
