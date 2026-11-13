# Authorizer and protocol threat review

Status: internal review complete for the current prototype; independent review
pending

This review covers the code and active manifest at commit time. It is not an
external audit and does not authorize production use. Findings that describe a
disabled feature are still tracked so an interface cannot silently become a
release claim.

## Assets and trust boundaries

The protected assets are author and administrator signing keys, HPKE recipient
and epoch keys, exact signed transaction bytes, validator evidence, feed
continuity, the canonical transaction order, the replicated
`chronolog_transactions` log, the published Dolt head, and operator
credentials.

The principal boundaries are:

1. unauthenticated network bytes to authenticated, signed feed records;
2. authenticated outer feed identity to the inner Chronolog signer;
3. signed protocol bytes to capability- and policy-authorized candidates;
4. authored SQL to the pinned engine and its authorizer block-list;
5. candidate replay state to the atomic published Dolt head;
6. local RPC callers to submission, query and governance authority;
7. JSON references to OS-held private material;
8. signed snapshot archives to locally trusted state; and
9. build source and lockfiles to release evidence.

## Reviewed controls

| Threat | Control and executable evidence | Residual boundary |
| --- | --- | --- |
| Non-canonical, oversized, or ambiguous protocol input | Strict bounded canonical CBOR; fixed-seed mutation fuzzing; versioned codecs | Coverage-guided native fuzzing remains scheduled release work |
| Feed impersonation or copied signed payload | Feed signatures and the SSB secret handshake, plus capability-revision binding of inner signer to exact outer feed | A feed-key compromise remains equivalent to that transport identity |
| Feed equivocation | Author/sequence/previous continuity registry; persistent quarantine; node becomes non-writable and degraded; signed-head snapshot repair accepts only a complete prefix and discards the recorded losing identity during rebuild | Operator signer/head selection and the repair ceremony require pilot evidence |
| Unauthorized SQL or protected-state access | Native authorizer block-list: attachments, transaction control, writing pragmas, temporary objects, Dolt functions and tables, `chronolog_*` writes, storage-reading modules; authorizer adversarial tests | A block-list admits everything else the pinned engine supports; a new engine build or patch must be reviewed against it |
| Ambient time/random/connection state | Fixed per-transaction inputs (`'now'` = author timestamp, seeded `random()`, UTC `localtime`, zeroed counters); `total_changes` and `sqlite_offset` denied; step and size limits | Any newly compiled-in function must be checked for ambient inputs before the manifest changes |
| Engine nondeterminism across replicas | One pinned DoltLite build named by the execution manifest; candidates for another manifest are rejected (`manifest_mismatch`); replay-equivalence conformance | Cross-platform (Linux/macOS) replay comparison remains a release gate |
| Partial candidate publication or crash | Private replay branch, independent reader verification, atomic head move, five-point `SIGKILL` matrix | Filesystem/hardware failure behavior still depends on the supported storage stack |
| Outcome substitution | Outcomes are recomputed by every replica from signed bytes and recorded in the replicated `chronolog_transactions` table; validators never sign database states | Stored-data format migration is intentionally absent in the prototype |
| Capability or epoch rollback | Signed revision chain, exact previous digest, epoch chain, monotonic validator timestamp floor | No in-protocol recovery: a lost or compromised root key is handled by forking the group or out of band |
| Plaintext daemon private keys | Reference-only v2 config/governance documents and Linux Secret Service migration; opt-in macOS Keychain, Windows DPAPI, and command-hook providers (fail closed, stdin-only secrets, write read-back) | The macOS/Windows/command providers are implemented but UNVERIFIED on real macOS, Windows, or hardware tokens; reference names appear in argv, macOS/DPAPI items are readable by any process of the same user, the Linux provider inherits the full environment, and a command helper is fully trusted |
| Snapshot rollback or foreign-state import | Fixed archive paths and hashes, authorized signature, group/manifest/no-rollback checks, staged production-adapter DB/log verification, fsynced atomic replacement and retained backup | Pilot restore/repair drill and platform filesystem qualification remain required |
| RPC credential disclosure or unauthenticated remote bind | Remote bind requires bearer token; timing-safe comparison; the metrics route shares authentication | Bearer tokens need deployment TLS/secret rotation outside this process |
| Dependency/build substitution | Pinned lockfile, native source checksum/patches, clean-worktree native archives, per-file verification, SBOM, subject hashes, package replacement drill, OIDC provenance attestations | A prior-release-to-candidate drill and publication ceremony require an actual earlier release |

## Findings and disposition

- `SEC-001` — Withdrawn. The threshold recovery mechanism it concerned was
  removed; root-key loss or compromise is handled by forking the group or out
  of band.
- `SEC-002` — Withdrawn. Blob replication was removed; large values travel
  inside ordinary records up to the configured maximum record size.
- `SEC-003` — Snapshot export/import now hashes fixed archive paths, validates a
  staged database against signed logical evidence, retains the old database,
  atomically replaces the materializer, and forces derived-state rebuild.
  Release evidence still needs a packaged pilot restore on each supported
  filesystem.
- `SEC-004` — Feed repair is now an offline signed-snapshot operation: the
  complete prefix must end at the signed head and resolve the recorded fork,
  while the losing identity is persistently discarded during replay. A pilot
  must execute and independently review the forensic repair ceremony.
- `SEC-005` — NAT discovery remains informational, but public deployments can
  now require a configured external HTTPS service to perform an SSB connection
  and return the exact observed server key; health degrades without the proof.
  The service is a trusted external vantage and does not create firewall/router
  mappings, so the pilot must qualify and monitor both mapping and verifier.
- `SEC-006` — Release workflows now build self-verifying platform archives,
  attest the archive and evidence, and run a packaged persistent-data
  replacement drill. Before the first non-bootstrap upgrade, run the same tool
  from the latest published artifact to the exact candidate; there is no prior
  release against which that evidence can yet be produced.
- `SEC-007` — The workerd/CAS implementation remains an experimental contract,
  not an active deployment target.
- `SEC-008` — Independent security review has not occurred. This is a release
  blocker even if all internal tests pass.

## Drill evidence signing domain

The `chronolog/drill-evidence/v1` signing domain was added to `DOMAINS` in
`packages/protocol/src/primitives.ts` for release drill records (see
[drill evidence](drill-evidence.md)). It is used only by `tools/drill.ts`, never
by consensus or daemon code. The tool proves tamper-evidence and key-holder
attestation only; it cannot show that distinct real people signed or that a
drill occurred.

## Review gate

Any change to protocol domains/codecs, capability admission, wire encryption,
the authorizer block-list, the pinned engine or its fixed inputs, the
publication sequence, snapshot trust, or secret storage must update this document and add or
identify executable evidence. An external reviewer must receive the exact
release commit, SBOM, provenance, conformance report, sanitizer/fuzz results,
and every unresolved finding above.
