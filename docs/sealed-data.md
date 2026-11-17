# Explicit readers and sealed values

Chronolog separates write ownership, application reader membership and access to
sealed plaintext. Owning a row does not hide its public fields. A reader with a
complete replica has the stored public values and ciphertext; private data must
be encrypted before publication.

## Two encryption boundaries

Application history and content use the session's committed epoch keys. Authorized
readers exchange missing keys through signed, scope-bound requests over peer
connections. The host is not a reader and does not receive those keys.

Sealed row values add an explicit recipient policy inside that history. The
canonical envelope commits the policy, algorithm, nonce, ciphertext and wrapped
recipient keys. The deterministic executor validates the envelope and applicable
policy without receiving the plaintext key. Encryption and decryption are caller
operations using the shared crypto and protocol packages.

## Changes and recovery

Changing a reader policy is an explicit authorized control action. New private
values must use the current policy and recipient set. Previously disclosed
plaintext and retained decryption keys cannot be revoked. Publishing private data
in a public field or ordinary event exposes it to every current application reader;
a later permission change cannot undo that disclosure.

The signed control chain remains monotonic across application recovery. A selected
older data prefix does not restore a removed reader's current authorization.
Historical ciphertext remains interpretable under its committed historical policy;
new serving and key delivery requests recheck current authority.

## Implementation boundaries

Canonical sealed encodings and validation live in `packages/protocol/src/sealed.ts`.
Recipient encryption and envelope verification live in `packages/crypto`.
Deterministic SQL authorization lives in `packages/materializer-doltlite` and uses
the same logic with native and WASM engines. Public application ownership and
key lifecycle remain in the [session](../packages/peer-session/README.md).
