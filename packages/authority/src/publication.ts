import type { BytesStore } from '@chronolog/records'
import type { AuthorityProvider } from './control.js'
import { check, decodeRecord, encodeRecord, equalRecord, hex, recordDigest, signRecord, verifyRecord, type Signed, type SigningIdentity } from './codec.js'
export const PUBLICATION_LIMITS = Object.freeze({ files: 128, bytes: 8 * 1024 * 1024, manifestBytes: 256 * 1024, revisions: 4096 })
export interface PublicationFile { readonly path: string; readonly hash: string; readonly size: number; readonly type: string }
export interface PublicationManifest {
  readonly applicationId: string
  readonly membershipId: string
  readonly author: string
  readonly operationId: string
  readonly revision: number
  readonly previous: string | null
  readonly executionManifestDigest: string
  /** Optional API label, never a database schema/admission lock. */
  readonly definitionLabel?: string
  readonly entry: string
  readonly files: readonly PublicationFile[]
}
export interface SignedPublication extends Signed<PublicationManifest> { readonly id: string }
function path(value: string): void { check(typeof value === 'string' && value.length > 0 && value.length <= 1024 && !/[\\?#%]/u.test(value) && value.split('/').every(part => part.length > 0 && part !== '.' && part !== '..'), 'PUBLICATION_PATH_INVALID') }
export function validatePublicationManifest(value: PublicationManifest): PublicationManifest {
  hex(value.applicationId); hex(value.membershipId); hex(value.author); hex(value.executionManifestDigest)
  check(typeof value.operationId === 'string' && value.operationId.length > 0 && value.operationId.length <= 512 && Number.isSafeInteger(value.revision) && value.revision >= 0, 'PUBLICATION_INVALID')
  if (value.previous !== null) hex(value.previous)
  check((value.previous === null) === (value.revision === 0), 'PUBLICATION_CHAIN_INVALID')
  path(value.entry); check(value.files.length > 0 && value.files.length <= PUBLICATION_LIMITS.files, 'PUBLICATION_FILES_LIMIT')
  let previous = '', total = 0
  for (const file of value.files) { path(file.path); hex(file.hash); check(file.path > previous && Number.isSafeInteger(file.size) && file.size >= 0 && typeof file.type === 'string' && /^[a-z][a-z0-9!#$&^_.+-]*\/[a-z0-9][a-z0-9!#$&^_.+-]*(?:;[ -~]*)?$/iu.test(file.type), 'PUBLICATION_FILE_INVALID'); previous = file.path; total += file.size }
  check(total <= PUBLICATION_LIMITS.bytes && value.files.some(file => file.path === value.entry) && encodeRecord(value).length <= PUBLICATION_LIMITS.manifestBytes, 'PUBLICATION_BYTES_LIMIT')
  return structuredClone(value)
}
export async function signPublicationManifest(value: PublicationManifest, identity: SigningIdentity): Promise<SignedPublication> {
  const payload = validatePublicationManifest(value); check(payload.author === identity.publicKey, 'PUBLICATION_SIGNER_MISMATCH')
  const signed = await signRecord('publication', payload, identity); return { ...signed, id: await recordDigest(['publication', payload]) }
}
export interface PublicationAuthority {
  readonly applicationId: string
  readonly executionManifestDigest: string
  /** Independent host-verified publisher grant revision. No data reader/writer/root key is required. */
  readonly grantId: string
  readonly publisherKeys: readonly string[]
}
function publicationScope(authority: AuthorityProvider | PublicationAuthority): PublicationAuthority {
  if ('descriptor' in authority) return { applicationId: authority.descriptor.applicationId, executionManifestDigest: authority.descriptor.executionManifestDigest, grantId: authority.currentMembershipId, publisherKeys: authority.currentMembership.members.filter(member => member.publisher).map(member => member.publicKey) }
  return authority
}
export async function verifyPublicationManifest(value: SignedPublication, authority: AuthorityProvider | PublicationAuthority): Promise<void> {
  const payload = validatePublicationManifest(value.payload), scope = publicationScope(authority)
  check(payload.applicationId === scope.applicationId && payload.executionManifestDigest === scope.executionManifestDigest, 'PUBLICATION_SCOPE_MISMATCH')
  check('descriptor' in authority ? authority.grant(payload.author, payload.membershipId)?.publisher : scope.grantId === payload.membershipId && scope.publisherKeys.includes(payload.author), 'PUBLICATION_PUBLISHER_REQUIRED')
  check(value.id === await recordDigest(['publication', payload]), 'PUBLICATION_ID_INVALID'); await verifyRecord('publication', value, payload.author)
}
export async function authorizePublication(value: SignedPublication, authority: AuthorityProvider | PublicationAuthority, previous: SignedPublication | null): Promise<void> {
  await verifyPublicationManifest(value, authority)
  const scope = publicationScope(authority)
  check(value.payload.membershipId === scope.grantId && scope.publisherKeys.includes(value.payload.author), 'PUBLICATION_AUTHORITY_CHANGED')
  check(value.payload.previous === (previous?.id ?? null) && value.payload.revision === (previous === null ? 0 : previous.payload.revision + 1), 'PUBLICATION_CONFLICT')
}
export async function verifyPublicationAsset(file: PublicationFile, bytes: Uint8Array): Promise<void> { path(file.path); hex(file.hash); const { sha256, bytesToHex } = await import('@chronolog/canonical'); check(bytes.length === file.size && bytesToHex(await sha256(bytes)) === file.hash, 'PUBLICATION_ASSET_MISMATCH') }
export interface PublicationRegistry { read(): Promise<readonly SignedPublication[]>; publish(value: SignedPublication): Promise<SignedPublication> }
export async function createPublicationRegistry(options: { readonly store: BytesStore; readonly authority: AuthorityProvider }): Promise<PublicationRegistry> {
  const key = `authority/${options.authority.descriptor.applicationId}/publications`; let tail: Promise<unknown> = Promise.resolve()
  const read = async (): Promise<SignedPublication[]> => {
    const bytes = await options.store.get(key), values = bytes === null ? [] : decodeRecord<SignedPublication[]>(bytes)
    check(values.length <= PUBLICATION_LIMITS.revisions, 'PUBLICATION_HISTORY_LIMIT')
    for (const [i, value] of values.entries()) { await verifyPublicationManifest(value, options.authority); check(value.payload.revision === i && value.payload.previous === (values[i - 1]?.id ?? null), 'PUBLICATION_CHAIN_INVALID') }
    return values
  }
  return { read, publish(input) {
    const value = structuredClone(input)
    const task = tail.then(async () => {
      const values = await read(), retry = values.find(item => item.payload.operationId === value.payload.operationId)
      if (retry !== undefined) { check(equalRecord(retry, value), 'PUBLICATION_OPERATION_REUSED'); return retry }
      await authorizePublication(value, options.authority, values.at(-1) ?? null); check(values.length < PUBLICATION_LIMITS.revisions, 'PUBLICATION_HISTORY_LIMIT')
      await options.store.put(key, encodeRecord([...values, value])); return structuredClone(value)
    }); tail = task.catch(() => undefined); return task
  } }
}
