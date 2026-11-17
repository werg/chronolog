import { decryptEpochPayload, encryptEpochPayload } from '@chronolog/crypto'
import {
  DOMAINS, decodeTransactionCore, encodeTransactionCore, equalBytes, isPlatformOp,
  transactionDigest, type TransactionCore,
} from '@chronolog/protocol'
import {
  boundedText, bytesDigest, bytesToHex, check, encodePeerValue, hex, hexToBytes,
  object, peerDigest, signPeerValue, uint, verifyPeerValue,
} from './codec.js'
import { type PeerAuthority, validateHistoryPoint } from './control.js'
import type { AttemptEnvelope, AttemptHeader, PeerIdentity, PeerRevision, SignedAttempt } from './types.js'

export function validatePeerRevision(value: PeerRevision): void {
  object(value, ['applicationId', 'historyId', 'generation', 'point', 'controlRevision', 'materializationRevision'])
  hex(value.applicationId); boundedText(value.historyId, 128); hex(value.generation); uint(value.controlRevision)
  validateHistoryPoint(value.point)
  check(value.point.generation === value.generation, 'PEER_REVISION_INVALID')
  check(typeof value.materializationRevision === 'string' && /^[0-9]{1,32}$/u.test(value.materializationRevision), 'PEER_REVISION_INVALID')
}
function validateHeader(value: AttemptHeader): void {
  object(value, ['applicationId', 'profile', 'generation', 'controlRevision', 'epoch', 'author', 'operationId',
    'definitionDigest', 'command', 'commandVersion', 'observedRevision', 'reapplyOf', 'coreDigest'])
  hex(value.applicationId); hex(value.generation); uint(value.controlRevision); uint(value.epoch)
  hex(value.author); boundedText(value.operationId); hex(value.definitionDigest); hex(value.coreDigest)
  boundedText(value.command, 128); boundedText(value.commandVersion, 128)
  if (value.observedRevision !== null) validatePeerRevision(value.observedRevision)
  if (value.reapplyOf !== null) hex(value.reapplyOf)
  check(value.profile === 'peer-generation-v1', 'PEER_PROFILE_UNSUPPORTED')
}
export async function createSignedAttempt(header: AttemptHeader, core: TransactionCore, key: Uint8Array, device: PeerIdentity): Promise<SignedAttempt> {
  validateHeader(header)
  check(header.author === device.publicKey && header.operationId === core.operationId, 'PEER_AUTHOR_MISMATCH')
  const plaintext = encodeTransactionCore(core)
  check(header.coreDigest === bytesToHex(await transactionDigest(plaintext)), 'PEER_ATTEMPT_CORE_MISMATCH')
  const encrypted = await encryptEpochPayload(key, BigInt(header.epoch), plaintext, encodePeerValue(header))
  const payload: AttemptEnvelope = { header: structuredClone(header), nonce: bytesToHex(encrypted.nonce), ciphertext: bytesToHex(encrypted.ciphertext) }
  const signed = await signPeerValue(DOMAINS.peerAttempt, payload, device)
  return { ...signed, id: await peerDigest(['chronolog/peer-generation/attempt/v1', payload]) }
}
/** Checks origin and historical authorization; ordering/admission checks are separate. */
export async function verifyAttempt(attempt: SignedAttempt, authority: PeerAuthority, epochKeys: ReadonlyMap<number, Uint8Array>): Promise<TransactionCore> {
  object(attempt, ['payload', 'signature', 'id']); hex(attempt.id)
  object(attempt.payload, ['header', 'nonce', 'ciphertext']); validateHeader(attempt.payload.header); hex(attempt.payload.nonce, 12)
  check(typeof attempt.payload.ciphertext === 'string' && attempt.payload.ciphertext.length <= 2 * 524_288 &&
    attempt.payload.ciphertext.length >= 32 && /^(?:[0-9a-f]{2})+$/u.test(attempt.payload.ciphertext), 'PEER_ATTEMPT_BODY_INVALID')
  const { header } = attempt.payload, descriptor = authority.descriptor
  check(header.applicationId === descriptor.applicationId && header.definitionDigest === descriptor.definitionDigest, 'PEER_SCOPE_MISMATCH')
  const generation = authority.generation(header.generation), control = authority.controlAt(generation.payload.controlRevision)
  check(header.controlRevision === control.payload.revision && header.epoch === control.payload.epoch, 'PEER_ATTEMPT_CONTROL_MISMATCH')
  if (header.observedRevision !== null) {
    const observed = header.observedRevision, observedGeneration = authority.generation(observed.generation)
    check(observed.applicationId === descriptor.applicationId && observed.historyId === descriptor.historyId &&
      observed.controlRevision === observedGeneration.payload.controlRevision &&
      observedGeneration.payload.number <= generation.payload.number, 'PEER_REVISION_INVALID')
  }
  check(authority.grant(header.author, header.controlRevision)?.writer === true, 'PEER_AUTHOR_FORBIDDEN')
  check(attempt.id === await peerDigest(['chronolog/peer-generation/attempt/v1', attempt.payload]), 'PEER_ATTEMPT_ID_INVALID')
  await verifyPeerValue(DOMAINS.peerAttempt, { payload: attempt.payload, signature: attempt.signature }, header.author)
  const key = epochKeys.get(header.epoch); check(key !== undefined, 'PEER_EPOCH_KEY_UNAVAILABLE')
  check(await bytesDigest(key) === control.payload.keyDigest, 'PEER_EPOCH_KEY_MISMATCH')
  const encoded = await decryptEpochPayload(key, { epoch: BigInt(header.epoch), nonce: hexToBytes(attempt.payload.nonce),
    ciphertext: hexToBytes(attempt.payload.ciphertext) }, encodePeerValue(header))
  const core = decodeTransactionCore(encoded)
  check(header.coreDigest === bytesToHex(await transactionDigest(encoded)) && core.operationId === header.operationId &&
    bytesToHex(core.authorId) === header.author && bytesToHex(core.groupId) === descriptor.applicationId &&
    bytesToHex(core.executionManifestDigest) === descriptor.executionManifestDigest &&
    bytesToHex(core.membershipRevision) === await peerDigest(control) &&
    bytesToHex(core.validationPolicy) === await peerDigest([descriptor.profile, descriptor.policy]) &&
    equalBytes(encodeTransactionCore(core), encoded), 'PEER_ATTEMPT_CORE_MISMATCH')
  // Security-sensitive changes are not ordinary lossy application operations.
  // SQL DDL is additionally fenced by the native/WASM author's profile.
  check(!core.program.steps.some(isPlatformOp), 'PEER_PROTECTED_CHANGE_REQUIRED')
  return core
}
