import type { BytesStore } from '@chronolog/records'
import { generateX25519KeyPair, exportX25519PrivateKey, importX25519PrivateKey, hpkeSealBase, hpkeOpenBase, type HpkeCiphertext } from '@chronolog/crypto'
import { check, bytesToHex, hexToBytes, encodeRecord, decodeRecord, recordDigest, signRecord, verifyRecord, type SigningIdentity, type Signed, type AuthorityProvider, type AuthorityBundle } from '@chronolog/authority'
export interface ProvisioningRequest { readonly applicationId: string; readonly descriptorId: string; readonly requestId: string; readonly recipient: string; readonly agreementPublicKey: string }
export type SignedProvisioningRequest = Signed<ProvisioningRequest>
export interface ProvisioningPackage { readonly request: SignedProvisioningRequest; readonly authority: AuthorityBundle; readonly encrypted: HpkeCiphertext }
export type SignedProvisioningPackage = Signed<ProvisioningPackage>
export interface ApplicationProvisioning { createProvisioningRequest(): Promise<SignedProvisioningRequest>; exportProvisioning(request: SignedProvisioningRequest): Promise<SignedProvisioningPackage>; importProvisioning(value: SignedProvisioningPackage): Promise<void> }
/** Recipient agreement secrets stay in this owned private store, including across uncertain replies/restarts. */
export function createApplicationProvisioning(options: { readonly store: BytesStore; readonly authority: AuthorityProvider; readonly identity: SigningIdentity }): ApplicationProvisioning {
  const { authority, identity, store } = options, prefix = `provisioning/${authority.descriptor.applicationId}`
  const context = (request: SignedProvisioningRequest): Uint8Array => encodeRecord(['provisioning', request])
  let tail: Promise<unknown> = Promise.resolve()
  const serial = <T>(work: () => Promise<T>): Promise<T> => { const task = tail.then(work); tail = task.catch(() => undefined); return task }
  return {
    createProvisioningRequest: () => serial(async () => {
      // Public key proof requests are allowed before enrollment; export is the disclosure gate.
      const indexRaw = await store.get(`${prefix}/requests`), ids = indexRaw === null ? [] : decodeRecord<string[]>(indexRaw)
      check(ids.length < 8, 'PROVISIONING_REQUEST_LIMIT')
      const pair = await generateX25519KeyPair(), requestId = crypto.randomUUID()
      const request = await signRecord('provisioning-request', { applicationId: authority.descriptor.applicationId, descriptorId: authority.descriptorId, requestId, recipient: identity.publicKey, agreementPublicKey: bytesToHex(pair.publicKeyBytes) }, identity)
      await store.put(`${prefix}/${requestId}`, encodeRecord({ request, privateKey: await exportX25519PrivateKey(pair.privateKey) }))
      await store.put(`${prefix}/requests`, encodeRecord([...ids, requestId])); return request
    }),
    exportProvisioning: request => serial(async () => {
      await verifyRecord('provisioning-request', request, request.payload.recipient)
      check(request.payload.applicationId === authority.descriptor.applicationId && request.payload.descriptorId === authority.descriptorId && authority.grant(request.payload.recipient)?.reader && authority.grant(identity.publicKey)?.reader && /^[0-9a-f]{64}$/u.test(request.payload.agreementPublicKey), 'PROVISIONING_SCOPE_INVALID')
      const epochs = [...new Set(authority.bundle().memberships.map(item => item.payload.epoch))]
      const keys = epochs.map(epoch => { const key = authority.epochKey(epoch); check(key !== null, 'PROVISIONING_SENDER_KEY_MISSING'); return [epoch, key] as const })
      const encrypted = await hpkeSealBase(hexToBytes(request.payload.agreementPublicKey), encodeRecord(keys), context(request), context(request))
      return signRecord('provisioning-package', { request, authority: authority.bundle(), encrypted }, identity)
    }),
    importProvisioning: value => serial(async () => {
      await verifyRecord('provisioning-package', value)
      const request = value.payload.request
      await verifyRecord('provisioning-request', request, identity.publicKey)
      check(request.payload.recipient === identity.publicKey && request.payload.applicationId === authority.descriptor.applicationId && request.payload.descriptorId === authority.descriptorId && /^[0-9a-f-]{36}$/u.test(request.payload.requestId), 'PROVISIONING_RECIPIENT_MISMATCH')
      const raw = await store.get(`${prefix}/${request.payload.requestId}`); check(raw !== null, 'PROVISIONING_REQUEST_MISSING')
      const saved = decodeRecord<{ request: SignedProvisioningRequest; privateKey: Uint8Array }>(raw)
      check(await recordDigest(saved.request) === await recordDigest(request), 'PROVISIONING_REQUEST_MISMATCH')
      await authority.merge(value.payload.authority)
      check(authority.grant(value.signer)?.reader && authority.grant(identity.publicKey)?.reader, 'PROVISIONING_READER_REQUIRED')
      const rawKeys = decodeRecord<unknown>(await hpkeOpenBase(await importX25519PrivateKey(saved.privateKey, false), hexToBytes(request.payload.agreementPublicKey), value.payload.encrypted.encapsulatedKey, value.payload.encrypted.ciphertext, context(request), context(request)))
      check(Array.isArray(rawKeys) && rawKeys.length <= 4096, 'PROVISIONING_KEYS_INVALID')
      const values: readonly unknown[] = rawKeys, seen = new Set<number>()
      for (const item of values) {
        check(Array.isArray(item) && item.length === 2, 'PROVISIONING_KEYS_INVALID')
        const entry: readonly unknown[] = item, epoch = entry[0], key = entry[1]
        check(typeof epoch === 'number' && Number.isSafeInteger(epoch) && !seen.has(epoch) && key instanceof Uint8Array, 'PROVISIONING_KEYS_INVALID'); seen.add(epoch)
        // Provider verifies authenticated epoch commitments before durable installation.
        await authority.installEpochKey(epoch, key)
      }
      // Retain the exact private request so a lost import reply can be retried unchanged.
    }),
  }
}
