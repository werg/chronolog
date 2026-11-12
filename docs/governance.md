# Replicated Governance

Chronolog's default daemon profile derives authorization and encryption state
from signed administration records carried by the same durable SSB transport as
transaction traffic. Static membership files are an explicit compatibility
override, not the normal multi-node control plane.

## Bootstrap and key storage

On first start, `chronologd` writes `governance.json` with mode `0600`. It
contains the signed genesis and the local HPKE reader key. The genesis gives the local identity administrator,
schema-administrator, writer, validator, and audit-reader capabilities and
binds those protocol keys to the daemon's authenticated SSB feed.

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

## When the ordinary path fails

There is no in-protocol recovery mechanism. The root administrator rotates its
own key or administration feed with an ordinary signed revision, and replaces
validators the same way. If the root key is lost or compromised, the validator
set can no longer satisfy its policy, or history below a closed timestamp floor
must be admitted, participants coordinate out of band or fork. Forking means
starting a new group with its own genesis, seeded from an agreed snapshot of the
old one. There is no dedicated fork tool yet; see
[snapshot-recovery.md](snapshot-recovery.md) for exporting snapshots.

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
  "readerScope": "snapshot",
  "hpkePublicKey": "BASE64URL_X25519_PUBLIC_KEY"
}
```

Reader grants require a scope and HPKE public key. Validator grants default
their minimum author timestamp to the daemon's current time unless an explicit
unsigned decimal value is supplied. Epoch keys are generated inside the
daemon and never returned by RPC.

`GovernanceControlPlane` in `@chronolog/node-core` backs that surface:

- `publishCapabilityChange` atomically grants roles, revokes capability IDs,
  installs validation policies, or transfers the root/feed;
- `revoke` removes every selected active capability at the next revision;
- `rotateEpoch` publishes a fresh content key wrapped independently to every
  active reader;
- `grantHistoricalAccess` rewraps retained epochs only for an active audit
  reader.

Every controller rebuilds the same revision snapshots and epoch chain from
transport history and follows new records live. Capability records and epoch
manifests must originate on the signed current administration feed.

## Removal and history policy

Revocation immediately prevents new writes and validator proofs at the new
membership revision. Rotate the epoch after removing a reader: the removed
device may retain plaintext and old epoch keys it already possessed, but it is
not included in the new manifest and cannot decrypt later traffic.

A snapshot reader receives only epochs explicitly published to it while its
grant is active. An audit reader may receive historical keys through an
explicit rewrap. Historical access never changes old transaction bytes.

A new validator's timestamp floor may not be lower than the floors of the
active validators. Admitting history below a closed floor requires a fork.

## Static override

Setting `CHRONOLOG_STATIC_MEMBERSHIP_FILE` disables the replicated governance
profile for that process. This is useful for compatibility tests and controlled
fixtures, but changes require matching file distribution and restarts. Do not
mix static and governed nodes as though they shared one live membership model.
