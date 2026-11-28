# `@chronolog/crypto`

Pure-JS + WebCrypto cryptographic primitives for Chronolog (zero native C/C++ builds; runs identically in Node.js >= 22.15, browsers, and Cloudflare Workers).

## Exports

- **Signing & Verification:** Ed25519 signing/cached verification (`signEd25519Sync`, `verifyEd25519Sync`, `deriveEpochMailboxKeyPair`), NIST P-256 WebAuthn DER/compact signature verification (`verifyP256Sync`), and `hmacSha256Sync`.
- **HPKE & Hybrid Post-Quantum X-Wing:** Classical `DHKEM(X25519)/HKDF-SHA256/AES-256-GCM` (`hpkeSealBase`, `hpkeOpenBase`) and hybrid post-quantum X-Wing (`ML-KEM-768 + X25519`, `generateXWingKeyPair`, `xwingPublicKeyFromSeed`, `xwingSealBase`, `xwingOpenBase`).
- **Key-Tagged TreeKEM (`keytree.ts`):** Sub-linear $O(\log N)$ CRDT-native group key rotation (`buildTreeEpochUpdate`, `openTreeEpoch`, `writeKeyTreeToCas`, `readKeyTreeFromCas`) over structural-sharing CAS Merkle-DAGs (`chronolog-keytree-dag/v1`).
- **Epoch AEAD & Recovery:** 192-bit HKDF per-operation AES-256-GCM encryption with optional power-of-2 bucket padding (`encryptEpochPayload`, `decryptEpochPayload`) and GF(256) Shamir Secret Sharing (`splitSecret`, `combineShares`).
