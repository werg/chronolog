# Sealed values

Chronolog separates two encryption layers:

1. **Epoch encryption**: encrypts application history and content attachments for all current readers using committed epoch keys exchanged peer-to-peer. The control host never receives epoch keys.
2. **Sealed row values**: encrypts individual fields for an explicit subset of recipients inside application history.

## How sealed values work

- Callers encrypt (`sealSealedValue`) and decrypt (`openSealedValue`) using `@chronolog/crypto`.
- The canonical CBOR envelope commits the recipient policy, HPKE suite, nonce, ciphertext, and per-recipient key wraps.
- The deterministic SQL executor validates the envelope structure and policy without ever holding plaintext keys (`packages/protocol/src/sealed.ts`, `packages/materializer-doltlite`).

## Policy changes and limits

- Updating a reader policy applies to new writes; previously disclosed plaintext or retained keys cannot be revoked.
- Control revisions are monotonic: recovering an earlier data prefix never restores a removed reader's current access.
- Public fields and ordinary events are visible to all application readers; never copy sealed plaintext into them.
