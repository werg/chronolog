import * as ed from '@noble/ed25519'
import { p256 } from '@noble/curves/nist.js'
import { hkdf } from '@noble/hashes/hkdf'
import { hmac } from '@noble/hashes/hmac'
import { sha256 } from '@noble/hashes/sha256'
import { sha512 } from '@noble/hashes/sha512'
import { protocolInvariant, utf8 } from '@chronolog/protocol'

ed.hashes.sha512 = (message: Uint8Array) => sha512(message) as Uint8Array<ArrayBuffer>

/**
 * Chronolog's single Ed25519 verification rule set (RFC 8032 / FIPS 186-5 strict, noble `zip215: false`):
 * canonical `A` and `R` encodings (`y < p`), `S < L`, small-order public keys rejected, cofactored
 * group equation. Every replica, reducer (`chronolog:crypto`), and blind host must verify with exactly
 * this function so signature acceptance is a deterministic function of the bytes.
 */
export function verifyEd25519Sync(publicKey: Uint8Array, message: Uint8Array, signature: Uint8Array): boolean {
  if (publicKey.length !== 32 || signature.length !== 64) return false
  try {
    return ed.verify(signature, message, publicKey, { zip215: false })
  } catch {
    return false
  }
}

/** Synchronous Ed25519 signing from a 32-byte seed (used for per-epoch anonymous mailbox tags). */
export function signEd25519Sync(seed32: Uint8Array, message: Uint8Array): Uint8Array {
  protocolInvariant(seed32.length === 32, 'INVALID_KEY', 'Ed25519 seed must be 32 bytes')
  return Uint8Array.from(ed.sign(message, seed32))
}

/** Derive the 32-byte Ed25519 public key synchronously from a 32-byte seed. */
export function ed25519PublicKeyFromSeedSync(seed32: Uint8Array): Uint8Array {
  protocolInvariant(seed32.length === 32, 'INVALID_KEY', 'Ed25519 seed must be 32 bytes')
  return Uint8Array.from(ed.getPublicKey(seed32))
}

/** Synchronous HMAC-SHA256 for pure deterministic QuickJS reducers. */
export function hmacSha256Sync(key: Uint8Array, message: Uint8Array): Uint8Array {
  return Uint8Array.from(hmac(sha256, key, message))
}

/** Wire format of an ECDSA P-256 signature: ASN.1 DER (WebAuthn / ES256 attestations) or 64-byte IEEE P1363 `r || s`. */
export type P256SignatureFormat = 'der' | 'compact'

/**
 * Synchronous ECDSA P-256 (ES256 / WebAuthn passkey) verification with an explicit signature format.
 * Accepts 33-byte compressed or 65-byte uncompressed SEC1 public keys. `compact` requires exactly
 * 64 bytes; `der` requires a strictly parsed ASN.1 DER `SEQUENCE { r, s }` (8..72 bytes).
 *
 * High-S signatures are accepted because WebAuthn authenticators are not required to normalize S.
 * ECDSA signatures are therefore malleable: never use P-256 signature bytes as an identifier or
 * deduplication key.
 */
export function verifyP256Sync(
  publicKey: Uint8Array,
  message: Uint8Array,
  signature: Uint8Array,
  format: P256SignatureFormat,
): boolean {
  if (publicKey.length !== 33 && publicKey.length !== 65) return false
  if (format === 'compact') {
    if (signature.length !== 64) return false
  } else if (format === 'der') {
    if (signature.length < 8 || signature.length > 72 || signature[0] !== 0x30) return false
  } else {
    return false
  }
  try {
    return p256.verify(signature, message, publicKey, { format, lowS: false })
  } catch {
    return false
  }
}

const MAILBOX_SIGNER_INFO = utf8('chronolog/mailbox-signer/v1')

/**
 * Deterministically derive an epoch's non-decrypting anonymous mailbox authentication keypair
 * from `epochKey`. Publishing `publicKey` in `$keys.epochs[epoch].mailboxVerifyKey` lets blind
 * hosts reject non-member mailbox spam while hiding writer identity (`author` = all zeros) and
 * leaking zero bits of `epochKey`.
 */
export function deriveEpochMailboxKeyPair(epochKey: Uint8Array): {
  readonly seed: Uint8Array
  readonly publicKey: Uint8Array
} {
  protocolInvariant(epochKey.length === 32, 'INVALID_KEY', 'Epoch key must be 32 bytes')
  const seed = Uint8Array.from(hkdf(sha256, epochKey, new Uint8Array(0), MAILBOX_SIGNER_INFO, 32))
  const publicKey = ed25519PublicKeyFromSeedSync(seed)
  return { seed, publicKey }
}
