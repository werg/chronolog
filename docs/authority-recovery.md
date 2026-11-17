# Fixed-authority recovery rehearsal

The first coordinated profile acknowledges one durable native store. It does
not promise survival of the permanent loss of that store, an automatic authority
replacement, or a second durable copy before acknowledgment. A signed prefix
certificate authenticates ordered descriptors; it does not attest that another
machine retains their detached application envelopes.

The executable rehearsal below covers the native implementation boundary of
[contrib issue #16](https://github.com/werg/tendriller-contrib/issues/16). Its
published report separates those observations from the deployed storage,
operator and Cloudflare evidence still required by that issue.

## Run and preserve the rehearsal

From a checked-out, installed Chronolog commit with the native SQL addon built:

```sh
pnpm exec tsx tools/authority-recovery.ts \
  --output artifacts/authority-recovery/my-run
```

Disposable private volumes default to a separate
`artifacts/authority-recovery-private` directory on the checkout's filesystem.
Pass `--volume-root /mounted/disposable-rehearsals` to exercise a chosen test
volume. The report records its filesystem type. The volume root must be outside
the publishable output directory; every per-run private volume is removed at the
end. Never point this drill at an existing application data directory.

The output directory must be new. The command exits nonzero on any failed
assertion and writes `report.json`, `process-traces.json` and a SHA-256/size
manifest even after a scenario fails. The report records the exact source
commit/tree, whether tracked sources were dirty, Node/OS/filesystem identity,
commands, timings and the evidence for each check. Use a clean commit for
reviewable release evidence; do not relabel a development report as a clean run.
The Quality workflow runs the same command and preserves its output.

Secret-bearing temporary stores are separate from the publishable evidence and
are deleted after the run. Reports contain public identities, signed certificate
fields, SQL probe values, operation outcomes, counts and file digests. Do not
upload production databases, `governance.json`, private key stores or whole
daemon directories as ordinary CI artifacts.

The underlying regression gate is:

```sh
pnpm exec vitest run test/authority-recovery.integration.test.ts
```

### What actually runs

Each fixture uses the actual `NativeAgentStore`, `NativeAuthority`, governed
node, native DoltLite SQL materializer, durable original-operation journal,
control database and signed portable feed transport. Separate Node child
processes open the stores. The store is SQLite WAL with `synchronous=FULL` and
an exclusive connection fence. There is no simulated storage acknowledgment.

Twelve scenarios send **SIGKILL**, without graceful cleanup, at six observed
boundaries for both an accepted SQL/event operation and an operation whose final
SQL assertion rejects the whole transaction:

| Kill boundary | Required recovered order before replay |
| --- | --- |
| Before detached payload commit | Previous complete prefix |
| After detached payload commit | Previous complete prefix; an unreferenced payload may exist |
| Before ordered record commit | Previous complete prefix |
| After ordered record commit | Prefix includes the original new descriptor |
| After prefix certificate commit | Prefix includes the original new descriptor and its certificate |
| After final application outcome, before caller acknowledgment | Original accepted/rejected result remains recoverable |

The parent reads the stopped database before any replay loop can repair it.
Restart then completes the original prepared operation. Exact retries preserve
its proposal, position, final outcome, SQL values and effective events, without
another ordered record. Changing contents under the original operation ID fails.
The rejected program's attempted row update and event never become final.

The operational command also runs seven separate checks:

- A second real process is refused while the first process owns the same store.
- Ordinary restart preserves identity, configuration, certificate, feed records,
  outcomes, SQL projection and payloads.
- A quiesced complete directory is copied, every regular file is fsynced and
  checked by size/hash, the old owner is removed, and a restored process reopens
  under an independently retained continuity floor. Accepted and rejected
  retries still return their originals.
- The actual authority runs in a separate process while two independently
  stored descriptor/certificate observers and a copied native SQL projection
  remain open. After **SIGKILL** and confirmed process exit, SQL reads still
  return the same final rows and one observer relays retained public evidence
  to the other. The observers/projection receive no authority signing key.
- Stopping the authority task preserves final SQL reads. Two independent
  ordering-policy stores verify and relay retained public evidence in reverse
  delivery order without supplied application bodies. A newly submitted
  operation remains unfinalized, then reaches finality after the authority
  restarts. This is an authority-task outage, not a public network outage.
- A separate observer store receives only descriptors/configuration/certificate.
  It recovers the same ordered head while every detached application body is
  absent. Its report explicitly makes no application replay claim.
- A separate test lineage keeps one current disk and one older backup. The
  current disk acknowledges another record and is deleted. Restoring the older
  backup under the separately retained latest head fails with
  `AUTHORITY_CONTINUITY_NOT_ESTABLISHED`. The report records the lag in records
  and elapsed time, then creates an explicit new lineage with a new identity.
  It does not claim recovery of the lost acknowledged operation.

The fixture uses embedded native storage and the portable feed adapter. It does
not start the SSB daemon or prove a production volume's network locking,
attachment, replication, snapshot consistency or power-loss guarantees. The
fault hooks surround the actual atomic storage calls; they do not stop a disk
controller during a sector write.

## Inventory the three recovery responsibilities

Use this inventory for the exact deployment being rehearsed. Record versions,
host/service identifiers, storage configuration, backup timestamps, public
identity fingerprints and who controls each role. Keep secret values outside
the report.

| Responsibility | Continuity that must survive | What restoring it does not establish |
| --- | --- | --- |
| Portable membership administrator; Cloudflare by default | Root signing identity, signed genesis/configuration, verified compact control history and signed checkpoint, roster and epoch state, exact enrollment/revocation decision journal, retained epoch keys and authorized wraps | Native authority continuity, SQL projection, detached bodies, or a second active administrator being safe |
| Native application authority and its agent | Pinned authority identity/configuration, complete ordered prefix and head, certificates, exact append deduplication, private operation/effect journals, signed feed history and encryption/key state; SQL/control state for immediate service recovery | Cloudflare membership-store continuity or another provider's blob durability |
| Full replicas and blob providers | Exact hash-committed application envelopes, retained encryption keys, signed feed/evidence needed for replay, application projection; blob/capture bytes plus independent availability/backup evidence | Roster authority or permission to reuse a lost native authority's identity/history |

In the embedded rehearsal, `agent.sqlite`, `control.sqlite`, `application.db`
and governance bootstrap files are captured together after all owners stop.
The actual daemon instead uses its fenced data directory and
`node-state.sqlite`; inventory **all** files and external secret references in
that deployment. Do not transplant fixture filenames into an operator command
and assume they enumerate the daemon's entire state.

[Application snapshot export](snapshot-recovery.md) intentionally contains an
application database and signed projection manifest, without daemon/authority
keys, feed history or operation journals. It is useful for its stated purpose;
it is insufficient as a complete authority backup.

## Partial metadata loss and the independent recovery floor

The native authority creates its durable empty log before saving configuration.
On reopening an established configuration, an absent log is a continuity failure,
not permission to restart the sequence. A surviving prefix certificate must
authenticate under that configuration and match the log at its certified
position. A damaged certificate, truncated prefix or conflicting replacement
fails closed without replacing the surviving configuration or proof. A still-open
log also refuses a missing underlying value. A committed append ahead of the
last saved certificate remains recoverable with its original retry position.

`packages/agent-service/src/native-authority.test.ts` exercises interrupted setup
before/after the empty-log and configuration writes, loss of an empty or certified
log, shorter/conflicting replacement logs, invalid encoding/kind/signature/configuration
in retained proof, and recovery of an append ahead of the last certificate. These
targeted metadata tests complement the real process-crash rehearsal above.

This local check protects against partial loss. A whole-volume rollback can
restore an internally consistent old log, configuration and certificate together.
Only an independently retained trusted floor can expose that staleness. The
procedure below still applies; a certificate copied from the same backup does
not establish freshness.

## Deployed single-writer and backup procedure

1. Record the pinned group/history and authority public key from verified
   configuration. Record the service, volume, filesystem and secret-store
   versions, plus the provider's actual locking and exclusive-attachment
   settings. Rehearse on disposable infrastructure with the same configuration.
2. Stop ingress and gracefully stop the old authority/agent before copying.
   Confirm the process is gone and the infrastructure prevents a second active
   attachment or restart. A PID check on one host is not a cross-host fence.
   The SQLite fence covers the same database file, not independent copied
   disks holding the same private identity.
3. Capture a consistent whole-state backup using that deployment's documented
   mechanism. Include external secret references and a separately secured key
   backup where applicable. Preserve a file/object manifest and verify a restore
   on an isolated host before calling the backup usable.
4. Independently record the latest **acknowledged** prefix, with its verified
   certificate and source/time, outside the volume and backup being restored.
   Record the difference between that floor and the backup head. A checkpoint
   copied from the same backup cannot reveal its own staleness. A peer's failure
   to show a newer certificate is not proof that none was acknowledged.
5. Restore only after fencing the old owner. Supply the trusted floor through
   `CHRONOLOG_AUTHORITY_CONTINUITY_FILE`, containing exactly the public
   `{ "historyId": "h_…", "position": N, "root": "…" }` fields. Obtain the
   floor from verified independent evidence; the JSON input itself is not an
   authentication mechanism. `NativeAuthority.open({ continuity })` checks
   that the restored prefix includes the same head at that position.
6. Verify the pinned configuration, certificates, exact retry outcomes,
   original-operation journals, feed continuity, roster/epoch activation, final
   SQL/event view and actual detached-body availability before reopening
   ingress. Exercise both a previously accepted and a previously rejected
   operation. Retain logs and diagnostics from the old and restored instances.

If the restored volume cannot prove continuity through every acknowledged
position, leave the old authority stopped. Reconstruct the complete proven
state from independently retained evidence only through an explicitly reviewed
recovery procedure, or create a new group/history lineage and perform an
explicit application recovery. The current implementation has no automatic
reconstruction/failover procedure and must not continue an old identity from an
unproven stale backup. Infrastructure uncertainty is not a final SQL rejection.

If the product later promises immediate survival of one disk's permanent loss,
first define which independent durable copies must acknowledge **before** a
client receives final acknowledgment. Then test power/storage failure and lost
responses against that exact contract. Replicating sometime afterward does not
establish it.

## Membership-store recovery and a portable host move

The actual packaged Cloudflare test already exercises approval-response loss,
Durable Object eviction/reopen, identical decision retry and refusal to change
the original operation. That does not export a production root key or prove a
portable host move. [Membership administration](governance.md) remains a
separate recovery responsibility.

For a deployed move, freeze new roster decisions; record the last certified
descriptor/roster/epoch/decision state; securely transfer a consistent complete
administrator store using a host-specific reviewed export; disable and fence
the old administrator before enabling the replacement. Compare the root public
key, pinned descriptor lineage, active roster, epoch/wrap availability and exact
completed enrollment/revocation operations. Drop a completed approval response
and retry its original operation ID on the replacement. A changed request under
that ID must fail. Do not copy the root key into two independently active
decision stores.

No general Cloudflare-to-native administrator export/import command is claimed
by this rehearsal. The live Cloudflare account, configured authentication,
backup/export permissions, secure key transfer and host fencing must be supplied
and exercised in the deployment setting. Reopening membership metadata must
leave native authority and detached-payload recovery status explicit; it cannot
stand in for either.

## Evidence still needed outside this environment

Attach a deployment report with actual service/version IDs, storage/secret
configuration, trusted checkpoint provenance, backup freshness and role owners.
Repeat the crash, outage and restore scenarios against the actual authority
process and persistent volume, including the provider's power/attachment failure
modes. Verify independent live peer reads while that process is gone. Rehearse
the actual Cloudflare membership backup and any host move separately, with one
active root store. Measure detached-body/blob replica availability and backup
lag independently of the small ledger. These observations require the real
infrastructure, operator permissions and storage guarantees; local and CI
reports do not close those deployed acceptance criteria.
