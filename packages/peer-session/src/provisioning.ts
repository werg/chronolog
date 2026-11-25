import { hpkeSealBase, hpkeOpenBase, type HpkeCiphertext } from '@chronolog/crypto'
export { createWrapKeyPair, importWrapPrivateKey, type WrapKeyPair } from './wrap-keys.js'
import { check, hexToBytes, encodeRecord, decodeRecord, signRecord, verifyRecord, verifyAuthorityBundle, type SigningIdentity, type Signed, type AuthorityProvider, type AuthorityBundle } from '@chronolog/authority'
/**
 * Every epoch key of an application, sealed to one member's signed key-wrap key.
 * The recipient and its wrap key come from authenticated membership, never from
 * the transport that carries the package.
 */
export interface KeyWrap { readonly applicationId: string; readonly descriptorId: string; readonly membershipId: string; readonly recipient: string; readonly wrapKey: string; readonly epochs: readonly number[]; readonly authority: AuthorityBundle; readonly encrypted: HpkeCiphertext }
export type SignedKeyWrap = Signed<KeyWrap>
export interface ApplicationProvisioning {
  /** Seal every epoch key this member holds to a current reader member's signed wrap key. */
  wrapKeys(recipient: string): Promise<SignedKeyWrap>
  /** Verify a package addressed to this device, merge its authority and install its committed epoch keys. */
  unwrapKeys(value: SignedKeyWrap, wrapPrivateKey: CryptoKey): Promise<readonly number[]>
}
const context = (value: Pick<KeyWrap, 'applicationId' | 'descriptorId' | 'membershipId' | 'recipient' | 'wrapKey' | 'epochs'>, sender: string): Uint8Array =>
  encodeRecord(['key-wrap', value.applicationId, value.descriptorId, value.membershipId, value.recipient, value.wrapKey, value.epochs, sender])
export function createApplicationProvisioning(options: { readonly authority: AuthorityProvider; readonly identity: SigningIdentity }): ApplicationProvisioning {
  const { authority, identity } = options
  let tail: Promise<unknown> = Promise.resolve()
  const serial = <T>(work: () => Promise<T>): Promise<T> => { const task = tail.then(work); tail = task.catch(() => undefined); return task }
  return {
    wrapKeys: recipient => serial(async () => {
      const grant = authority.grant(recipient), own = authority.grant(identity.publicKey)
      check(grant?.reader === true && grant.wrapKey !== null && own?.reader === true, 'PROVISIONING_SCOPE_INVALID')
      const epochs = [...new Set(authority.bundle().memberships.map(item => item.payload.epoch))].sort((a, b) => a - b)
      const keys = epochs.map(epoch => { const key = authority.epochKey(epoch); check(key !== null, 'PROVISIONING_SENDER_KEY_MISSING'); return [epoch, key] as const })
      const scope = { applicationId: authority.descriptor.applicationId, descriptorId: authority.descriptorId, membershipId: authority.currentMembershipId, recipient, wrapKey: grant.wrapKey, epochs }
      const info = context(scope, identity.publicKey)
      const encrypted = await hpkeSealBase(hexToBytes(grant.wrapKey), encodeRecord(keys), info, info)
      return signRecord('key-wrap', { ...scope, authority: authority.bundle(), encrypted }, identity)
    }),
    unwrapKeys: (value, wrapPrivateKey) => serial(async () => {
      await verifyRecord('key-wrap', value)
      const payload = value.payload
      check(payload.recipient === identity.publicKey && payload.applicationId === authority.descriptor.applicationId && payload.descriptorId === authority.descriptorId, 'PROVISIONING_RECIPIENT_MISMATCH')
      await verifyAuthorityBundle(payload.authority)
      await authority.merge(payload.authority)
      check(authority.hasMembership(payload.membershipId), 'PROVISIONING_SCOPE_INVALID')
      const at = authority.membership(payload.membershipId)!
      const sender = at.members.find(member => member.publicKey === value.signer), target = at.members.find(member => member.publicKey === identity.publicKey)
      check(sender?.reader === true && target?.reader === true && target.wrapKey === payload.wrapKey, 'PROVISIONING_READER_REQUIRED')
      const info = context(payload, value.signer)
      const rawKeys = decodeRecord<unknown>(await hpkeOpenBase(wrapPrivateKey, hexToBytes(payload.wrapKey), payload.encrypted.encapsulatedKey, payload.encrypted.ciphertext, info, info))
      check(Array.isArray(rawKeys) && rawKeys.length <= 4096 && rawKeys.length === payload.epochs.length, 'PROVISIONING_KEYS_INVALID')
      const installed: number[] = []
      for (const [index, item] of (rawKeys as readonly unknown[]).entries()) {
        check(Array.isArray(item) && item.length === 2, 'PROVISIONING_KEYS_INVALID')
        const entry: readonly unknown[] = item, epoch = entry[0], key = entry[1]
        check(typeof epoch === 'number' && epoch === payload.epochs[index] && key instanceof Uint8Array, 'PROVISIONING_KEYS_INVALID')
        // The provider verifies each authenticated epoch commitment before durable installation.
        if (authority.epochKey(epoch) === null) { await authority.installEpochKey(epoch, key); installed.push(epoch) }
      }
      return installed
    }),
  }
}
