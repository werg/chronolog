# Replicated Governance

Chronolog enrolls readers and writers while the group is running. Native and
browser replicas share signed requests, durable approvals, governance records,
encryption-key delivery and policy-specific activation through
`createGovernedNode`. The ordinary public client exposes this workflow through
`client.enrollment`.

The group's signed genesis fixes its history policy and execution profile.
Both built-in policies keep the root, administration feed, validator set and
validation policy fixed. Reader/writer membership and encryption epochs can
change live. Static membership is an explicit fixture/operator override.

## Thin membership administration

`MembershipAdministrator` is the portable implementation for a host that only
manages the roster. Tendriller runs it by default inside the existing Cloudflare
Durable Object for a configured resident peer application. The same component
can run on another administrator's machine: it needs Web Crypto, durable byte
storage and a connection to the group's pinned inclusion/finality service. It does not
need a SQL engine, an application replica or a separate deployed service.

The existing ordered ledger contains small typed records. A roster grant,
revocation or encrypted key delivery is a signed operation in that ledger.
An application operation contributes a descriptor with its hash, length and
encryption epoch; full replicas fetch its original envelope from peers by hash.
The administrator verifies every descriptor and processes inline roster and key
operations. It never asks for application bodies. Bandwidth therefore grows with
the number of descriptors and the number of recipients, independently of the
size of detached application bodies. See [typed ledger records](typed-ledger-records.md)
for byte limits and the exact verification rules.

Each device generates and retains its own signing key pair and HPKE reader key
pair. Its signed enrollment request contains the public keys. The administrator
generates shared content keys and encrypts each key to the approved readers'
public keys; it never needs their private keys. The administrator is trusted with
these shared content keys so it can rotate them and grant explicit historical
access. This design does not claim that the administrator is unable to decrypt
application data if it separately obtains the ciphertext.

The signed genesis names the roster issuer (`rootAdminPublicKey`), initial SQL
schema administrator (`schemaAdminPublicKey`), and native inclusion/finality signer
explicitly. Cloudflare's roster signer receives no implicit SQL membership.
The native application peer can own the schema and order the ledger while
Cloudflare only manages enrollment and delivers wrapped keys.

To bootstrap, `provisionMembership` durably creates the roster signer and public
descriptor from the native authority, execution profile, schema administrator
and optional initial **public** reader/writer grants. The native peer starts
from that descriptor. `MembershipAdministrator.open` then uses
`createMembershipLedgerClient` to append signed inline operations and read
certified descriptors through `POST /_chronolog/membership`. No reader grant is
required for this independently signed administration endpoint.

A joining device first verifies its grant and encrypted key delivery from that
small history. It can then authenticate a peer connection and fetch application
bodies. Governance activation continues while application replay waits for a
missing body; the missing body is pending progress, never a rejected operation.
Approvals and revocations retain their exact operation identities across lost
responses and restarts. Revocation and key rotation resume as one durable
administration operation.

`npm run package:membership` builds the standalone `@chronolog/membership`
artifact with bundled JavaScript, self-contained declarations and source/input
provenance. The package has no application engine or native transport dependency.
The Tendriller host consumes this public artifact, rather than another
repository's source files or an application-supplied implementation registry.

## Live enrollment

The joining device first loads the intended signed group descriptor and opens
its own durable signing and reader identity. A descriptor is public bootstrap
material, not permission to read or write. The device creates a signed request
using a stable request ID:

```ts
const { signedRequest } = await joiningDevice.enrollment.createRequest({
  requestId: durableJoinRequestId,
  roles: ['reader', 'writer'],
})
```

Deliver those exact bytes to an authorized issuer through the application's
invitation channel. Approval is an explicit decision about roles and historical
access, with its own stable operation ID:

```ts
const { signedApproval } = await issuer.enrollment.approveRequest({
  operationId: durableApprovalId,
  signedRequest,
  roles: ['reader', 'writer'],
  grantFullHistory: true,
})
```

Return the signed approval to the joining device. The status call persists it
before evaluating readiness; later calls can use just the request ID:

```ts
const status = await joiningDevice.enrollment.getStatus(durableJoinRequestId, {
  signedApproval,
})
const refreshed = await joiningDevice.enrollment.getStatus(durableJoinRequestId)
```

Keep those operation identities across lost replies and restarts. A resumed
approval publishes the original grants and key envelopes before its dependent
work; concurrent approvals cannot author competing next revisions or epochs.
The joining device's private keys remain local.

| State | What the joining replica still needs |
| --- | --- |
| `requested` | An issuer's signed decision. |
| `approved` | The approved membership revision to become active under the selected history policy. |
| `authorized-disconnected` | A usable connection for synchronization. |
| `awaiting-keys` | Explicit historical access and the required epoch keys. |
| `awaiting-history` | The captured final target to be verified and applied locally. |
| `unsupported-engine` | The execution profile required by the group. |
| `revoked` | The approval's exact grants are no longer active. |
| `ready` | Active grants, keys, connection, matching engine and applied final target are all present. |

Approval does not imply readiness. The issuer may go offline after the signed
records and approval are retained; another authorized peer can deliver the
history and key envelopes. A relay's host-access permission is separate from
Chronolog membership. The first enrollment workflow grants reader/writer roles,
not validators, governance administrators or schema-administrator rights.
Shared rows and schema access use the existing collective and ownership
operations described below. See the complete
[client guide](../packages/client/README.md#enroll-a-reader-or-writer).

## Bootstrap and key storage

On first start, `chronologd` writes `governance.json` with mode `0600`. It
contains the signed genesis and the local HPKE reader key. The genesis gives the local identity administrator,
writer, validator, and reader capabilities and binds those protocol keys to
the daemon's feed for the default single-participant peer configuration. The
genesis also authenticates the selected history policy and execution-manifest
digest. A coordinated group instead supplies its fixed history ID and authority
key in that configuration.

On Linux, set `CHRONOLOG_SECRET_STORE=secret-service` to keep the daemon
signing key, epoch content key, and governance recipient key in the host
Secret Service through `secret-tool`.
`CHRONOLOG_SECRET_SERVICE` optionally changes the service namespace. Existing
inline `config.json` and `governance.json` files are migrated atomically to
reference-only v2 documents on the first successful start. Secret values are
sent over stdin and never placed in process arguments.

The host needs `libsecret-tools`, a reachable Secret Service provider, and an
unlocked collection for the daemon account. Startup fails closed if a v2
document is opened without that provider or a referenced secret is missing.
Back up the keys before enabling migration; switching the environment back to
`file` does not copy secrets into JSON. One OS account is still one failure
domain.

### Other key providers (opt-in, unverified)

`CHRONOLOG_SECRET_STORE` also accepts `macos-keychain`, `windows-dpapi`, and
`command` (a hardware-token or vault helper named by an absolute
`CHRONOLOG_SECRET_COMMAND`, with optional JSON `CHRONOLOG_SECRET_COMMAND_ARGS`,
allow-listed `CHRONOLOG_SECRET_COMMAND_ENV` names, and
`CHRONOLOG_SECRET_COMMAND_TIMEOUT_MS`). They are implemented and covered by unit
tests against fake command runners and a real scripted child process on Linux,
but they are **UNVERIFIED on real macOS, Windows, or hardware tokens**. Treat
them as experimental until an operator has run them on the target host; no
release gate depends on them. Every write is read back, and an unknown provider,
a provider selected on the wrong platform, or a missing secret fails closed
rather than falling back to inline JSON. Secret values travel on stdin only;
tool stderr is dropped from errors for operations that carry secrets.

Residual exposures:

- Reference names, the service namespace, and any keychain path or helper fixed
  arguments appear in process arguments and are visible to the same user.
- macOS Keychain and Windows DPAPI protect against other users, not against
  other processes running as the daemon's own account, which can read the item.
  The Windows provider is a DPAPI-protected file store, not Credential Manager.
- The Linux Secret Service provider runs `secret-tool` with the daemon's full
  environment; the other providers run tools with a scrubbed environment.
- A `command` helper is fully trusted: it sees every secret and reference, and
  it alone is responsible for PIN handling, durability, and non-extractability.

## Schema administration and the `group` collective

Capability roles decide who may author, validate and read. What a writer may
do to the database's rows is decided inside the database
([owner-controlled rows](design-owner-rows.md)):

- The signed genesis `schemaAdminPublicKey` is the first admin of the **`group`
  collective** (id: 32 zero bytes), created when the materialized database is
  initialized. The daemon reads that explicit schema key from the genesis,
  or `rootAdministrator` from a static membership file. The roster issuer
  `rootAdminPublicKey` does not receive SQL ownership through its issuer role.
  Cloudflare provisioning names the native application owner's public key as
  schema administrator and keeps its own roster signing key separate.
- Active admins of the `group` collective are the **schema administrators**.
  Only they may run DDL (tables, indexes, views, app triggers, `ALTER TABLE`)
  (tables are owner-checked automatically). A group admin adds another with a `set_members` step
  (`{"platform":"set_members","collectiveId":"group","changes":[{"member":KEY,"role":"admin"}]}`);
  the new admin joins by submitting `accept_membership` for `group`.
- Schema administrators are not data owners. They cannot update or delete
  other keys' rows, or re-own them; they can only narrow access with app
  triggers.
- Revoking a node's `writer` capability prevents authoring at the new
  membership revision. Rows it owns stay owned by its key; a planned key
  change is a bulk transfer signed by the old key and accepted by the new one.
  See the revision and finality distinction below.

## Initial local configuration

Every node of a governed group must use the same signed genesis and group
route. Applications can distribute the public descriptor as bootstrap material.
The existing CLI can export and adopt that configuration:

```sh
# Export public configuration from an existing member's local data directory:
pnpm group descriptor /secure/group.json
# On the new node, with an empty data directory:
CHRONOLOG_DATA_DIR=/var/lib/chronolog pnpm group join /secure/group.json
```

These commands take an exclusive lock on the local data directory they open,
so that directory's daemon must be stopped while the command runs. This is
initial local setup; approving a new device does not require stopping other
replicas or rebuilding the group.

`join` creates the joining node's identity, feed and reader key and adopts the
genesis. Its suggested grant material is limited to ordinary reader/writer
membership. Configure a connection, such as the administrator's SSB address in
`CHRONOLOG_SSB_PEERS`, start the local replica, and complete
[live enrollment](#live-enrollment) through the shared client. Every member
replicates the administration feed and feeds named by grants. Only the
administration-feed owner authors capability revisions and epochs.

## When the ordinary path fails

Durable journals recover interrupted governance and approval without creating
new identities or competing revisions. Retained records and evidence let peers
rebuild local state and recover missing keys or history.

The built-in signed configurations do not provide root or authority rotation,
administration-feed replacement, validator reconfiguration or validation-policy
changes. Their authoring APIs reject these operations. If a fixed key is lost
or compromised, the validators can no longer satisfy their policy, or final
history must change, participants agree on a new group configuration out of
band and fork. An unavailable coordinated authority delays new finality;
existing complete certificates remain usable through other peers.

### Forking a group

A fork is a new group with its own genesis, seeded from an agreed signed
snapshot of the old one. The old group's history is untouched; the fork's
genesis records the source group, the snapshot manifest's SHA-256 and its
revision (`forkedFrom`), so anyone can see where it came from.

```sh
# 1. Agree on a snapshot out of band and export it from a member of the old group
#    (see snapshot-recovery.md): chronolog-snapshot export /secure/snapshot-r120
# 2. On the new group's first node, with an empty data directory:
CHRONOLOG_DATA_DIR=/var/lib/fork pnpm group fork /secure/snapshot-r120 --signer BASE64URL_SNAPSHOT_SIGNER
# 3. Start chronologd on /var/lib/fork, then seed it:
pnpm cli seed @/var/lib/fork/fork-seed.json
# 4. Optionally stop the daemon and confirm the data matches the snapshot:
CHRONOLOG_DATA_DIR=/var/lib/fork pnpm group verify-fork /secure/snapshot-r120
# 5. Other participants adopt the descriptor and complete live enrollment.
```

`fork` verifies the archive exactly like a snapshot import (file evidence, the
operator-chosen signer, execution manifest, materialized evidence) and makes
this node the fork's root administrator. It writes `fork-seed.json`
(`chronolog-fork-seed-v5`): transactions that recreate the
snapshot's application tables, then write their rows with the `seed_rows`
platform operation, in foreign-key order and keeping every row's
`chronolog_owner`, then the teams, memberships, grants and open transfer
offers, and finally the indexes, views and app triggers (after the rows, so
they do not fire during seeding). Each batch asserts that it has not been
applied yet and records itself in a `fork_seed` table, so `seed` can be rerun
safely after an interruption. Every replica of the fork replays the seed like
any other transaction.

`seed_rows` is accepted only from the fork's root administrator, and only until
the plan's last batch (`end_seeding`) or the first accepted transaction by any
other key, whichever comes first: **seed the fork before other participants
write to it.** After `end_seeding` not even the root can seed rows. Members keep their keys in the fork, so they still
own their rows. The old group's `group` collective is not carried over; the
fork's root administrator is its only schema administrator until it adds
others.

Limits: every table needs a primary key; foreign-key cycles between tables and
virtual tables are refused; Dolt commit history and `AUTOINCREMENT` counters of
the old group are not carried over. `verify-fork` compares every application
table, including owners, and the ownership state: registered tables, teams,
memberships, grants and transfer offers.

A snapshot containing any sealed reader-policy generation, including a closed
one, cannot currently be forked. Seed-plan creation fails with
`SEALED_DATA_REQUIRES_EXPLICIT_REENCRYPTION`: sealed envelopes authenticate the
source group, policy generation and version, so copying them into a new group
would not preserve their meaning. A future cross-group workflow must explicitly
decrypt and re-encrypt through authorized readers. Same-group snapshot restore
continues to preserve the complete database and its sealed metadata.

## Live operations

The daemon exposes the control plane through authenticated `governance.*` RPC
methods and the `chronolog governance` CLI. Remote administration uses the
same required bearer token as every other remote RPC; a static-membership node
fails these commands with `failed_precondition`.

```sh
pnpm cli governance status
pnpm cli governance grant @reader-grant.json
pnpm cli governance revoke CAPABILITY_ID
pnpm cli governance rotate
pnpm cli governance history SUBJECT_ID
```

A grant file contains public material only. For example:

```json
{
  "subjectId": "BASE64URL_SUBJECT_ID",
  "signingPublicKey": "BASE64URL_ED25519_PUBLIC_KEY",
  "transportAuthor": "@participant-feed.ed25519",
  "role": "reader",
  "hpkePublicKey": "BASE64URL_X25519_PUBLIC_KEY"
}
```

The protocol represents `writer`, `validator`, `reader` and `administrator`
roles. Reader grants require an HPKE public key. Live enrollment selects
reader/writer grants; the fixed validators are established in the signed
genesis. Epoch keys are generated inside the replica and are never returned
as plaintext by RPC.

`GovernanceControlPlane` in `@chronolog/node-core` backs that surface:

- `publishCapabilityChange` serializes and durably publishes supported grants
  and revocations; under a built-in signed configuration it rejects changes
  to validators, validation policy, root and administration feed;
- `revoke` removes every selected active capability at the next revision;
- `rotateEpoch` publishes a fresh content key wrapped independently to every
  active reader;
- `grantHistoricalAccess` rewraps retained historical epochs for an active
  reader; this is the only way a reader gets epochs from before its grant.
- `ownsCapabilityFeed` tells whether this node is the administration-feed
  owner, the only node that publishes capability revisions and epochs.

Every controller rebuilds signed revision snapshots and the epoch chain from
retained records and follows new records live. Ordinary peer delivery verifies
the configured administration feed and its complete prefix. Coordinated
delivery verifies the ordered record and its signed governance content through
the certified history. A replica may receive snapshots and key envelopes ahead
of activation; its active authorization still follows the history policy.
The fixed-history restrictions also apply to received root-signed revisions,
before they can mutate the received snapshot. An unsupported control occupies
its receipt without preventing a later valid revision from activating.

## Removal and history policy

Revocation takes effect at a verified activation point, not when a newer
snapshot happens to arrive:

- In peer mode, all fixed validators close the preceding revision with signed
  evidence. A replica verifies their complete preceding feed admissions and
  the resulting timestamp boundary before activating the next revision.
  Validators durably seal the old revision before publishing its closure.
- With a signed-inclusion provider, controls are reduced in their signed causal
  revision order and activate after their verified closed timestamp boundary.
  Receipt order does not choose membership or SQL order. Newly included
  backdated proposals at or below an already-closed cutoff are excluded.

Earlier final outcomes remain unchanged. A later regrant to the same signing
key creates a new capability; it cannot reactivate the revoked capability or
resurrect a rejected proposal. Governance receipt, authorization activation,
key availability and local application progress are separate conditions.

Rotate the epoch after removing a reader: the removed device may retain
plaintext and old epoch keys it already possessed, but it is not included in
the new manifest and cannot decrypt traffic encrypted with that new key.

Application acceptance also checks the epoch selected at the signed author
timestamp. A verified rotation governs timestamps after its closed boundary, even
when an earlier reader key remains available for historical replay. A still
authorized writer's envelope prepared under a closed epoch receives the final
rejection `ENCRYPTION_EPOCH_CLOSED` if its signed time is after that rotation.
A new inclusion behind an earlier closed cutoff instead receives
`FINALITY_TIMESTAMP_CLOSED`. Its
durable operation keeps the original signed bytes and proposal ID; retries do
not silently re-encrypt or create a new application operation. An application
can deliberately submit a fresh operation with a new ID after synchronizing.
An exact retry already finalized before the rotation retains its original outcome.

This is a rule for canonical acceptance. It cannot prevent a participant from
disclosing plaintext or old-key ciphertext it already knows. An unavailable
application body, or a missing local key for an epoch already issued at that
position, still blocks replay; it is not treated as a stale-epoch rejection.
The full envelope must be retrieved and checked against its committed hash and
metadata. An epoch not yet issued by the preceding canonical controls is
permanently invalid at that position, even if a later rotation or received key
wrap names it. Replicas skip that position without assigning an unverified
proposal identity. Previously issued epochs must still be decrypted before a
stale-epoch rejection can identify the original signed proposal.
Unknown or future membership revisions in an already verified canonical prefix
are unauthorized at that position. Malformed or out-of-order inline control
operations occupy their positions without holding up later valid controls.

Every active reader receives each new epoch at rotation. Earlier epochs reach
a reader only through an explicit `grantHistoricalAccess`. Historical access
never changes old transaction bytes.

When replaying a complete certified prefix, a late replica first receives its
verified governance and key envelopes. This lets a historical key grant later
in the prefix unlock earlier encrypted SQL. That receipt does not activate a
later writer grant early. Missing keys or an unsupported execution profile
remain explicit blocked states, not SQL rejections or false readiness.

### Row-grant revocation and finality

Row grants are revoked by ordinary ordered transactions. A write ordered after
a row-grant revoke sees the revoked grant. While the order is provisional,
late transactions can still be inserted earlier and cause a suffix to replay.
Once a blocking set of validators has closed the relevant timestamp prefix,
a newly admitted backdated write cannot be inserted before that revoke. This
is the existing finality mechanism; historical writes remain part of history.

`TransactionHandle.accepted()` and `settled()` report the materialized outcome
at the transaction's **current position**. Neither waits for finality. For an
irreversible decision, inspect settlement evidence: the relevant policy
watermark must cover the transaction (`confidence: 'policy_watermark_reached'`),
and unresolved referenced records must be accounted for. An accepted outcome
alone does not establish that its preceding history is closed.

Group capability revocations use the separate administration log. The node
normally authors against its latest membership revision; historical snapshots
remain available for replay. The current implementation can still admit a
fresh transaction explicitly pinned to an older membership revision when that
revision authorizes the signer and enough validators. Such a transaction can
reach provisional materialized state. Once honest validators move to the newer
revision, their new heartbeats do not advance the old revision's watermark, so
that fresh transaction does not become final through those heartbeats. This
revision-lifecycle boundary is distinct from rewriting an already closed
timestamp prefix or bypassing an ordered row-grant revoke.

## Static override

Setting `CHRONOLOG_STATIC_MEMBERSHIP_FILE` disables the replicated governance
profile for that process. This is useful for isolated tests and controlled
fixtures, but changes require matching file distribution and restarts. Do not
mix static and governed nodes as though they shared one live membership model.
