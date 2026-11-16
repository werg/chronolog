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

- The genesis root administrator is the first admin of the **`group`
  collective** (id: 32 zero bytes), created when the materialized database is
  initialized. The daemon reads the root key from the genesis
  (`rootAdminPublicKey`), or from `rootAdministrator` in a static membership
  file.
- Active admins of the `group` collective are the **schema administrators**.
  Only they may run DDL (tables, indexes, views, app triggers, `ALTER TABLE`)
  (tables are owner-checked automatically). A group admin adds another with a `set_members` step
  (`{"platform":"set_members","collectiveId":"group","changes":[{"member":KEY,"role":"admin"}]}`);
  the new admin joins by submitting `accept_membership` for `group`.
- Schema administrators are not data owners. They cannot update or delete
  other keys' rows, or re-own them; they can only narrow access with app
  triggers.
- Revoking a node's `writer` capability stops its new transactions. Rows it
  owns stay owned by its key; a planned key change is a bulk transfer signed by
  the old key and accepted by the new one.

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

## Removal and history policy

Revocation takes effect at a verified activation point, not when a newer
snapshot happens to arrive:

- In peer mode, all fixed validators close the preceding revision with signed
  evidence. A replica verifies their complete preceding feed admissions and
  the resulting timestamp boundary before activating the next revision.
  Validators durably seal the old revision before publishing its closure.
- In coordinated mode, the capability record's certified canonical position
  is the boundary. The new revision governs later positions. Backdating an
  author timestamp cannot restore a grant at a later position.

Earlier final outcomes remain unchanged. A later regrant to the same signing
key creates a new capability; it cannot reactivate the revoked capability or
resurrect a rejected proposal. Governance receipt, authorization activation,
key availability and local application progress are separate conditions.

Rotate the epoch after removing a reader: the removed device may retain
plaintext and old epoch keys it already possessed, but it is not included in
the new manifest and cannot decrypt traffic encrypted with that new key.

Every active reader receives each new epoch at rotation. Earlier epochs reach
a reader only through an explicit `grantHistoricalAccess`. Historical access
never changes old transaction bytes.

When replaying a complete certified prefix, a late replica first receives its
verified governance and key envelopes. This lets a historical key grant later
in the prefix unlock earlier encrypted SQL. That receipt does not activate a
later writer grant early. Missing keys or an unsupported execution profile
remain explicit blocked states, not SQL rejections or false readiness.

## Static override

Setting `CHRONOLOG_STATIC_MEMBERSHIP_FILE` disables the replicated governance
profile for that process. This is useful for isolated tests and controlled
fixtures, but changes require matching file distribution and restarts. Do not
mix static and governed nodes as though they shared one live membership model.
