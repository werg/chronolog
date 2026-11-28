/**
 * Materialized snapshot bundle v3: the wire/host format a fresh replica adopts as its starting
 * state (sync-v3 `snapshot` message, host-cached `materializedSnapshot`).
 *
 *   outer  = CBOR [3, logId, 0, signer, signature, body]              (public log)
 *          | CBOR [3, logId, 1, epoch, nonce, AES-GCM(CBOR [signer, signature, body])]  (private log)
 *   body   = CBOR [logId, cache, casNodes]
 *   cache  = encodeMaterializedCache(frontier-only kernel cache)        (no outcomes or events)
 *   casNodes = [[hash, partition (0 public | 1 private), encoded node], ...]
 *
 * The signature is Ed25519 over the body under domain `chronolog/materialized-snapshot/v3` by a
 * member device. Receivers verify it, check the signer is a member, and re-hash every CAS node.
 * Trust shortcut (documented in docs/PERFORMANCE.md): the receiver adopts the signed state as its
 * frontier without replaying the history it summarizes; facts it later receives are still
 * individually verified.
 */
import { bytesToHex, decodeCanonicalCbor, DEFAULT_DECODE_LIMITS, encodeCanonicalCbor, hexToBytes, type CborValue } from '@chronolog/canonical'
import { decryptEpochPayload, encryptEpochPayload } from '@chronolog/crypto'
import { DOMAINS, signDomain, utf8, verifyDomain } from '@chronolog/protocol'
import type { CasPartition } from '@chronolog/records'
import { decodeMaterializedCache, encodeMaterializedCache, type KernelMaterializedCache } from '@chronolog/materializer'

export interface SnapshotCasNode {
  readonly hash: string
  readonly bytes: Uint8Array
  readonly partition: CasPartition
}

export interface DecodedSnapshot {
  readonly signer: string
  readonly cache: KernelMaterializedCache
  readonly casNodes: readonly SnapshotCasNode[]
}

const SNAPSHOT_LIMITS = Object.freeze({ ...DEFAULT_DECODE_LIMITS, maxBytes: 256 * 1024 * 1024, maxBlobBytes: 256 * 1024 * 1024, maxArrayItems: 4_000_000 })

const aad = (logId: string, epoch: number): Uint8Array => utf8(`chronolog-v3-snapshot:${logId}:${epoch}`)

export async function encodeSnapshotBundle(input: {
  readonly logId: string
  readonly cache: KernelMaterializedCache
  readonly casNodes: readonly SnapshotCasNode[]
  readonly identity: { readonly publicKey: string; readonly privateKey: CryptoKey }
  readonly encryption?: { readonly epoch: number; readonly key: Uint8Array }
}): Promise<Uint8Array> {
  const logIdBytes = hexToBytes(input.logId)
  const body = encodeCanonicalCbor([
    logIdBytes,
    encodeMaterializedCache(input.cache),
    input.casNodes.map(node => [hexToBytes(node.hash), node.partition === 'public' ? 0n : 1n, node.bytes]),
  ])
  const signature = await signDomain(DOMAINS.materializedSnapshot, body, input.identity.privateKey)
  const signer = hexToBytes(input.identity.publicKey)
  if (input.encryption === undefined) return encodeCanonicalCbor([3n, logIdBytes, 0n, signer, signature, body])
  const plain = encodeCanonicalCbor([signer, signature, body])
  const enc = await encryptEpochPayload(input.encryption.key, BigInt(input.encryption.epoch), plain, aad(input.logId, input.encryption.epoch))
  return encodeCanonicalCbor([3n, logIdBytes, 1n, BigInt(input.encryption.epoch), enc.nonce, enc.ciphertext])
}

/** Peek at the outer envelope without decrypting (null when not a v3 bundle for `logId`). */
export function snapshotEnvelope(bytes: Uint8Array, logId: string): { readonly private: boolean; readonly epoch: number } | null {
  try {
    const outer = decodeCanonicalCbor(bytes, SNAPSHOT_LIMITS)
    if (!Array.isArray(outer) || outer[0] !== 3n || !(outer[1] instanceof Uint8Array) || bytesToHex(outer[1]) !== logId) return null
    if (outer[2] === 0n) return { private: false, epoch: -1 }
    if (outer[2] === 1n && typeof outer[3] === 'bigint') return { private: true, epoch: Number(outer[3]) }
    return null
  } catch {
    return null
  }
}

/**
 * Decode, decrypt (private logs) and verify the signature of a v3 bundle. Returns null for
 * anything malformed, for the wrong log, or when the epoch key is unavailable.
 */
export async function decodeSnapshotBundle(
  bytes: Uint8Array,
  logId: string,
  epochKey: (epoch: number) => Uint8Array | undefined,
): Promise<DecodedSnapshot | null> {
  try {
    const outer = decodeCanonicalCbor(bytes, SNAPSHOT_LIMITS)
    if (!Array.isArray(outer) || outer[0] !== 3n || !(outer[1] instanceof Uint8Array) || bytesToHex(outer[1]) !== logId) return null
    let signer: CborValue | undefined, signature: CborValue | undefined, body: CborValue | undefined
    if (outer[2] === 0n && outer.length === 6) {
      ;[, , , signer, signature, body] = outer as readonly CborValue[]
    } else if (outer[2] === 1n && outer.length === 6) {
      const [, , , epochRaw, nonce, ciphertext] = outer as readonly CborValue[]
      if (typeof epochRaw !== 'bigint' || !(nonce instanceof Uint8Array) || !(ciphertext instanceof Uint8Array)) return null
      const epoch = Number(epochRaw)
      const key = epochKey(epoch)
      if (key === undefined) return null
      const plain = await decryptEpochPayload(key, { epoch: epochRaw, nonce, ciphertext }, aad(logId, epoch))
      const inner = decodeCanonicalCbor(plain, SNAPSHOT_LIMITS)
      if (!Array.isArray(inner) || inner.length !== 3) return null
      ;[signer, signature, body] = inner as readonly CborValue[]
    } else {
      return null
    }
    if (!(signer instanceof Uint8Array) || signer.length !== 32 || !(signature instanceof Uint8Array) || !(body instanceof Uint8Array)) return null
    if (!await verifyDomain(DOMAINS.materializedSnapshot, body, signature, signer)) return null
    const decodedBody = decodeCanonicalCbor(body, SNAPSHOT_LIMITS)
    if (!Array.isArray(decodedBody) || decodedBody.length !== 3) return null
    const [bodyLogId, cacheBytes, rawNodes] = decodedBody as readonly CborValue[]
    if (!(bodyLogId instanceof Uint8Array) || bytesToHex(bodyLogId) !== logId || !(cacheBytes instanceof Uint8Array) || !Array.isArray(rawNodes)) return null
    const cache = decodeMaterializedCache(cacheBytes)
    if (cache === null || cache.logId !== logId) return null
    const casNodes: SnapshotCasNode[] = []
    for (const item of rawNodes) {
      if (!Array.isArray(item) || item.length !== 3) return null
      const [hash, partition, nodeBytes] = item as readonly CborValue[]
      if (!(hash instanceof Uint8Array) || hash.length !== 32 || (partition !== 0n && partition !== 1n) || !(nodeBytes instanceof Uint8Array)) return null
      casNodes.push({ hash: bytesToHex(hash), bytes: nodeBytes, partition: partition === 0n ? 'public' : 'private' })
    }
    return { signer: bytesToHex(signer), cache, casNodes }
  } catch {
    return null
  }
}
