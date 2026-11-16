# Explicit readers and sealed row data

Sealed data adds an explicit reader policy to an owner-controlled application
row. The client encrypts a value before submitting it. The replicated program
contains a ciphertext envelope and wrapped keys; replicas do not receive its
plaintext or the readers' private keys.

Write authority and read access are separate. The row's owner or owning team's
administrator controls its reader policy. A writer still needs the ordinary
authority to update the target column, including any column-scoped grant and
application trigger checks. Neither ownership, team membership, schema
administration nor the root key automatically makes a participant a reader.

This is not SELECT filtering. Replicas can inspect row identifiers, owners,
reader policies, public encryption keys, ciphertext sizes, update timing and
the ciphertext itself. Only an explicitly wrapped reader with the matching
private HPKE key can use the provided decryption helper to recover a value.
Application fields that need server-side predicates, joins, indexes or
constraints must remain available to SQL. Triggers on a sealed column see
ciphertext bytes.

## Keys and identities

A reader is identified by its existing 32-byte signing key. It registers a
separate X25519 public key using `register_reader_key`, signed by that reader's
node. The supplied public key replaces that signer's registered encryption key.
Registration does not silently change existing policies: each policy version
snapshots the registered keys of its selected readers.

The current app API still submits transactions as the node's signing key.
Consequently a reader registering a key needs permission to publish a
transaction, including the group's writer capability. This feature does not
introduce independently authenticated users behind a shared node.

Private key creation and persistence remain the application's responsibility.
Keep the private key on the reader's device or in its key store; never put it in
SQL, a platform operation or an RPC request. Losing the private key can make
previously sealed values unreadable. Registering a replacement key and refreshing
a policy affects subsequent values; it does not recover older keys.

## Basic client workflow

The example assumes `alice` and `bob` are `ChronologClient` instances for two
authorized nodes in the same group. Alice owns the application row. Use the
column's declared name exactly for the `slot` argument.

```ts
import { generateX25519KeyPair } from '@chronolog/crypto'
import { SealedPolicyNotFinalError } from '@chronolog/client'

// These private keys stay in their respective reader applications.
const aliceHpke = await generateX25519KeyPair(false)
const bobHpke = await generateX25519KeyPair(false)
await (await alice.sealed.registerKey(aliceHpke.publicKeyBytes)).accepted()
await (await bob.sealed.registerKey(bobHpke.publicKeyBytes)).accepted()

await (await alice.transaction([
  'CREATE TABLE notes (id INTEGER PRIMARY KEY, body BLOB) STRICT',
  'INSERT INTO notes (id) VALUES (1)',
])).accepted()

// Include Alice explicitly if she should be able to decrypt her own writes.
const readers = [await alice.identity(), await bob.identity()]
const created = await alice.sealed.setReaders({
  table: 'notes', row: [1n], readers, expectedVersion: 0n,
})
await created.handle.accepted()

// put() additionally requires the policy update's accepted outcome to be below
// a resolved policy watermark. accepted() alone is not that finality condition.
// If necessary, observe created.handle.evidence until the condition is met.
try {
  const change = await alice.sealed.put(
    created.id, 'body', new TextEncoder().encode('A private note'),
    { expectedPolicyVersion: 1n, expectedDataVersion: 0n },
  )
  await change.handle.accepted()
} catch (error) {
  if (error instanceof SealedPolicyNotFinalError) {
    // Wait for policy_watermark_reached, no unresolved references, and an
    // accepted outcome, then explicitly retry the operation.
  } else {
    throw error
  }
}

// Once this value has replicated to Bob's node:
const value = await bob.sealed.get(created.id, 'body')
if (value !== null) {
  const plaintext = await bob.sealed.decrypt(value, bobHpke.privateKey)
  console.log(new TextDecoder().decode(plaintext))
}
```

`put()` returns `{ handle, context }`. The context identifies the exact group,
policy generation, policy version, column and data version that were encrypted.
`put()` and `sealSealedValue()` take independent snapshots of their byte inputs
before asynchronous work. Node `Buffer` values and subviews are supported:
encryption consumes only the supplied view, and temporary plaintext cleanup
does not erase the caller's buffer.

An application that requires this exact version can retain that context and
pass it as the fourth argument to `decrypt(value, privateKey, readerId,
expectedContext)`. An ordinary latest-value read uses the independently stored
version metadata returned by the node. As with other local reads, this is not a
proof against a malicious node serving stale history.

`getPolicy(table, primaryKeyValues)` resolves the row's actual stored primary key
using SQL and returns its current open policy, or `null`. `policy(policyId)` reads
a particular generation, including one closed by deletion or a primary-key
change. Values in an owner-containing primary key use the actual SQL column
value at this API boundary, just like other platform row lookups; the stored
opaque key uses stable owner keys internally.

## Changing the audience

Changes use compare-and-swap over both the policy generation id and version.
Creation requires `expectedVersion: 0n` and no expected id. A replacement names
the observed policy id and positive version. A concurrent change rejects the
transaction instead of silently replacing another participant's audience.

```ts
const current = await alice.sealed.getPolicy('notes', [1n])
if (current === null) throw new Error('No reader policy')

const changed = await alice.sealed.setReaders({
  table: 'notes', row: [1n],
  readers: [await alice.identity()], // Bob is omitted from future values.
  expectedPolicyId: current.policyId,
  expectedVersion: current.version,
})
await changed.handle.accepted()
// Wait for policy settlement before the next put(), which checks it by default.
```

Every `put` generates a fresh random AES-256-GCM content key. It wraps that key
separately with HPKE to exactly the current policy's snapshotted public keys.
Removing Bob therefore stops the normal client from wrapping subsequent value
keys to him. It does not remove his old keys, erase his plaintext or prevent him
from decrypting older envelopes. Adding a reader likewise does not grant access
to old envelopes automatically: an existing reader must decrypt and reseal any
history that should be shared.

Replacing a registered reader key also requires a policy refresh to take effect.
Keep old private keys if old values must remain decryptable. An empty reader
policy is allowed and blocks subsequent sealed puts. The backend and high-level
encryption helper both refuse a value with no readers, avoiding an accidental
unrecoverable write.

Ownership transfer retains the policy generation and its explicit reader set.
Its controller becomes the new row owner or owning team's administrator. A new
owner is not given the plaintext automatically. If the owner is a component of
the primary key, the protected policy row-key reference follows that ownership
transfer. An ordinary primary-key change or deletion closes the generation;
reusing the primary key creates a distinct policy id. Closed generations retain
their historical ciphertext but cannot accept new writes.

## Publication is the confidentiality boundary

Encryption and key wrapping happen before the transaction is published, outside
deterministic SQL execution. After publication, the candidate itself contains
the ciphertext and reader wraps. A recipient can attempt decryption even when
the transaction later fails a row-write check, a trigger or compare-and-swap.
SQL rollback and deterministic replay cannot withdraw those bytes.

For that reason `put()` checks the policy update's settlement evidence before
encrypting. Its default requires an accepted outcome,
`confidence === 'policy_watermark_reached'` and no unresolved references.
Otherwise it throws `SealedPolicyNotFinalError` without encrypting or submitting
the value. Tests or development tools can explicitly pass
`allowProvisionalPolicy: true`; that permits irreversible disclosure under a
policy that may later change during replay.

The finality check settles the selected policy snapshot. It cannot make a later
audience change atomic with a client's read, encryption and publication. If a
concurrent removal takes effect first, a put using the old snapshot can be
rejected while its published wraps remain decryptable by that snapshot's
recipients. Treat encryption as an explicit decision to disclose to the selected
audience, and use expected policy/data versions to catch already-observed
changes. Do not interpret a rejected transaction as a promise that no reader
received its secret.

Sealing a column that previously contained plaintext does not erase the old SQL
transaction, database revisions, snapshots or copies. Start with an empty BLOB
column when historical confidentiality matters. An authorized writer who
already knows a secret can always deliberately publish it elsewhere; envelope
validation is not a proof that arbitrary bytes were correctly encrypted.

## Replicated state and validation

The protocol adds three operations with reserved codes 64–66:

| Operation | Purpose |
| --- | --- |
| `register_reader_key` | Register/replace the actor's own 32-byte public HPKE key. |
| `reader_policy` | Create or replace the explicit reader set for one row, with generation/version CAS. |
| `sealed_put` | Check policy/data versions and exact reader/key wraps, then write a sealed BLOB column. |

The protected state is queryable through ordinary local reads:

| Table | Contents |
| --- | --- |
| `chronolog_reader_keys` | Signing key to currently registered HPKE public key. |
| `chronolog_reader_policies` | Row reference, policy generation/version, update transaction and closure. |
| `chronolog_policy_readers` | Explicit reader ids and snapshotted HPKE public keys for the policy. |
| `chronolog_sealed_values` | Current envelope and per-column data/policy versions for each generation. |

The application column contains the encoded envelope too. A sealed put follows
ordinary column-update authorization and application triggers. Once a column
has been sealed, protected guards reject direct SQL replacement of that value;
the matching sealed operation provides the narrowly scoped write exemption.
Private keys and plaintext are never part of this sidecar state.

The envelope's authenticated context includes the group id, policy id, policy
version, column and data version. HPKE key wraps additionally bind the reader id
and its public key. Decryption requires an expected context from the caller; it
does not accept an envelope's self-declared group as authority. Canonical codecs
reject unknown critical fields, duplicate or unsorted reader wraps, malformed
key/nonce/tag lengths and inconsistent versions.

The supported limits are 256 readers, 1 MiB of plaintext per value, 128 UTF-8
bytes for a table/column name and positive signed 64-bit versions. Data versions
increase separately per policy id and column. Encryption randomness is chosen
only on the client; replicas replay the same submitted ciphertext bytes.

Same-group snapshot recovery preserves the context and ciphertext. Cross-group
fork seeding is refused when reader policies exist: copying ciphertext into a
new group would require an explicit resealing/migration design and fresh reader
key trust decisions. Merely relabeling an envelope with a new group cannot make
it valid there.
