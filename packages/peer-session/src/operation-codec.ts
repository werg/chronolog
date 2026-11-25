import { type AuthorityProvider, type Signed, type SigningIdentity, bytesToHex, hexToBytes, check, encodeRecord, decodeRecord, recordDigest, signRecord, verifyRecord, writerAuthorizedAt } from '@chronolog/authority'
import { encryptEpochPayload, decryptEpochPayload, type EncryptedEpochPayload } from '@chronolog/crypto'
import { decodeTransactionCore, encodeTransactionCore, transactionDigest, type TransactionCore } from '@chronolog/protocol'
export interface SignedOperationBody { readonly proposalId: string; readonly canonicalCore: Uint8Array }
export type SignedOperation = Signed<SignedOperationBody>
export interface OperationEnvelope {
  readonly applicationId: string
  readonly proposalId: string
  readonly author: string
  readonly authorTimestampMs: bigint
  readonly membershipId: string
  readonly executionManifestDigest: string
  readonly encrypted: EncryptedEpochPayload
}
export type SignedOperationEnvelope = Signed<OperationEnvelope>
export async function signOperation(core: TransactionCore, identity: SigningIdentity): Promise<SignedOperation> {
  const canonicalCore = encodeTransactionCore(core), proposalId = bytesToHex(await transactionDigest(canonicalCore))
  check(bytesToHex(core.authorId) === identity.publicKey, 'OPERATION_SIGNER_MISMATCH')
  return signRecord('operation', { proposalId, canonicalCore }, identity)
}
export async function verifyOperation(body: SignedOperation): Promise<TransactionCore> {
  await verifyRecord('operation', body)
  const core = decodeTransactionCore(body.payload.canonicalCore)
  check(bytesToHex(core.authorId) === body.signer && bytesToHex(await transactionDigest(body.payload.canonicalCore)) === body.payload.proposalId, 'OPERATION_IDENTITY_INVALID')
  return core
}
export function membershipAt(authority: AuthorityProvider, id: string, timestamp: bigint, author: string): 'valid' | 'pending' | 'invalid' {
  const valid = writerAuthorizedAt(authority, author, id, timestamp)
  return valid === null ? 'pending' : valid ? 'valid' : 'invalid'
}
function aad(applicationId: string, proposalId: string): Uint8Array { return encodeRecord(['operation-envelope', applicationId, proposalId]) }
export async function wrapOperation(body: SignedOperation, identity: SigningIdentity, epoch: number, key: Uint8Array): Promise<SignedOperationEnvelope> {
  const core = await verifyOperation(body)
  check(body.signer === identity.publicKey, 'OPERATION_SIGNER_MISMATCH')
  const applicationId = bytesToHex(core.groupId)
  const payload: OperationEnvelope = { applicationId, proposalId: body.payload.proposalId, author: body.signer, authorTimestampMs: core.authorTimestampMs, membershipId: bytesToHex(core.membershipRevision), executionManifestDigest: bytesToHex(core.executionManifestDigest), encrypted: await encryptEpochPayload(key, BigInt(epoch), encodeRecord(body), aad(applicationId, body.payload.proposalId)) }
  return signRecord('operation-envelope', payload, identity)
}
export async function verifyEnvelope(envelope: SignedOperationEnvelope, authority: AuthorityProvider): Promise<'valid' | 'pending' | 'excluded'> {
  await verifyRecord('operation-envelope', envelope, envelope.payload.author)
  const value = envelope.payload, descriptor = authority.descriptor
  hexToBytes(value.proposalId); check(/^[0-9a-f]{64}$/u.test(value.proposalId) && value.applicationId === descriptor.applicationId && value.executionManifestDigest === descriptor.executionManifestDigest && typeof value.authorTimestampMs === 'bigint' && value.authorTimestampMs >= 0n && value.authorTimestampMs <= (1n << 63n) - 1n && value.encrypted.epoch >= 0n && value.encrypted.epoch <= BigInt(Number.MAX_SAFE_INTEGER), 'OPERATION_SCOPE_INVALID')
  const membership = membershipAt(authority, value.membershipId, value.authorTimestampMs, value.author)
  if (membership === 'pending') return 'pending'
  const base = authority.membership(value.membershipId)!
  check(value.authorTimestampMs > base.authorTimeAfterMs && authority.grant(value.author, value.membershipId)?.writer === true, 'OPERATION_WRITER_FORBIDDEN')
  if (membership === 'invalid') return 'excluded'
  return authority.bundle().memberships.some(item => item.payload.epoch === Number(value.encrypted.epoch)) ? 'valid' : 'pending'
}
export async function unwrapOperation(envelope: SignedOperationEnvelope, authority: AuthorityProvider): Promise<{ readonly body: SignedOperation; readonly core: TransactionCore; readonly admission: 'valid' | 'excluded' } | 'authority' | 'key'> {
  const admission = await verifyEnvelope(envelope, authority)
  if (admission === 'pending') return 'authority'
  const value = envelope.payload, key = authority.epochKey(Number(value.encrypted.epoch))
  if (key === null) return 'key'
  const body = decodeRecord<SignedOperation>(await decryptEpochPayload(key, value.encrypted, aad(value.applicationId, value.proposalId)))
  const core = await verifyOperation(body)
  check(body.payload.proposalId === value.proposalId && body.signer === value.author && core.authorTimestampMs === value.authorTimestampMs && bytesToHex(core.membershipRevision) === value.membershipId && bytesToHex(core.groupId) === value.applicationId && bytesToHex(core.executionManifestDigest) === value.executionManifestDigest && bytesToHex(core.validationPolicy) === await recordDigest(['finality-policy', authority.descriptor.finalityPolicy]), 'OPERATION_ENVELOPE_MISMATCH')
  return { body, core, admission }
}
