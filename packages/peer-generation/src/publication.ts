import type { BytesStore } from '@chronolog/records'
import { DOMAINS } from '@chronolog/protocol'
import {
  boundedText, bytesDigest, check, decodePeerValue, encodePeerValue, hex, isArray, object,
  peerDigest, samePeerValue, Serial, signPeerValue, uint, verifyPeerValue,
} from './codec.js'
import { assertAuthorityExtension, verifyAuthorityBundle, type PeerAuthority } from './control.js'
import { PEER_GENERATION_PROFILE, type AuthorityBundle, type PeerIdentity, type Signed } from './control-types.js'

export const PUBLICATION_LIMITS = Object.freeze({ files: 128, bytes: 8 * 1024 * 1024, manifestBytes: 256 * 1024,
  revisions: 256, historyBytes: 16 * 1024 * 1024 })
export interface PublicationFile {
  readonly path: string
  readonly hash: string
  readonly size: number
  readonly type: string
}
/** Presentation can evolve independently; executable application semantics stay descriptor-bound. */
export interface PublicationManifest {
  readonly applicationId: string
  readonly historyId: string
  readonly profile: typeof PEER_GENERATION_PROFILE
  readonly controlRevision: number
  readonly author: string
  readonly operationId: string
  readonly revision: number
  readonly previous: string | null
  readonly definitionDigest: string
  readonly executionManifestDigest: string
  readonly entry: string
  readonly files: readonly PublicationFile[]
}
export interface SignedPublication extends Signed<PublicationManifest> { readonly id: string }

function path(value: unknown): asserts value is string {
  boundedText(value, 1024)
  check(!/[\\?#%]/u.test(value) && value.split('/').every(part => part.length > 0 && part !== '.' && part !== '..'),
    'PEER_PUBLICATION_PATH_INVALID')
}
export function validatePublicationManifest(input: unknown): PublicationManifest {
  object(input, ['applicationId', 'historyId', 'profile', 'controlRevision', 'author', 'operationId', 'revision', 'previous',
    'definitionDigest', 'executionManifestDigest', 'entry', 'files'])
  const value = input as PublicationManifest
  hex(value.applicationId); boundedText(value.historyId, 128); hex(value.author); boundedText(value.operationId, 128)
  check(value.profile === PEER_GENERATION_PROFILE, 'PEER_PROFILE_UNSUPPORTED')
  uint(value.controlRevision); uint(value.revision, PUBLICATION_LIMITS.revisions - 1)
  if (value.previous !== null) hex(value.previous)
  check((value.revision === 0) === (value.previous === null), 'PEER_PUBLICATION_CHAIN_INVALID')
  hex(value.definitionDigest); hex(value.executionManifestDigest); path(value.entry)
  check(isArray(value.files) && value.files.length > 0 && value.files.length <= PUBLICATION_LIMITS.files, 'PEER_PUBLICATION_FILES_LIMIT')
  let previous: string | undefined, total = 0
  for (const file of value.files) {
    object(file, ['path', 'hash', 'size', 'type']); path(file.path); hex(file.hash); uint(file.size, PUBLICATION_LIMITS.bytes)
    boundedText(file.type, 256)
    check(/^[a-z][a-z0-9!#$&^_.+-]*\/[a-z0-9][a-z0-9!#$&^_.+-]*(?:;[ -~]*)?$/iu.test(file.type), 'PEER_PUBLICATION_TYPE_INVALID')
    check(previous === undefined || previous < file.path, 'PEER_PUBLICATION_FILES_NOT_ORDERED')
    previous = file.path; total += file.size
  }
  check(total <= PUBLICATION_LIMITS.bytes, 'PEER_PUBLICATION_BYTES_LIMIT')
  check(value.files.some(file => file.path === value.entry), 'PEER_PUBLICATION_ENTRY_MISSING')
  check(encodePeerValue(value).length <= PUBLICATION_LIMITS.manifestBytes, 'PEER_PUBLICATION_MANIFEST_LIMIT')
  return structuredClone(value)
}

export async function signPublicationManifest(input: PublicationManifest, signer: PeerIdentity): Promise<SignedPublication> {
  const payload = validatePublicationManifest(input)
  check(payload.author === signer.publicKey, 'PEER_PUBLICATION_AUTHOR_MISMATCH')
  const signed = await signPeerValue(DOMAINS.peerPublication, payload, signer)
  return { ...signed, id: await peerDigest(['chronolog/publication/v1', signed.payload]) }
}

/** Historical validity survives a later administrator change; acceptance uses authorizePublication. */
export async function verifyPublicationManifest(input: SignedPublication, authority: PeerAuthority): Promise<void> {
  const publication = structuredClone(input)
  object(publication, ['payload', 'signature', 'id']); hex(publication.id)
  const value = validatePublicationManifest(publication.payload), descriptor = authority.descriptor
  check(value.applicationId === descriptor.applicationId && value.historyId === descriptor.historyId &&
    value.profile === descriptor.profile, 'PEER_PUBLICATION_SCOPE_MISMATCH')
  check(value.definitionDigest === descriptor.definitionDigest && value.executionManifestDigest === descriptor.executionManifestDigest,
    'PEER_PUBLICATION_SEMANTICS_MISMATCH')
  check(authority.grant(value.author, value.controlRevision)?.administrator === true, 'PEER_PUBLICATION_FORBIDDEN')
  check(publication.id === await peerDigest(['chronolog/publication/v1', value]), 'PEER_PUBLICATION_ID_INVALID')
  await verifyPeerValue(DOMAINS.peerPublication, { payload: value, signature: publication.signature }, value.author)
}

/** Select a new release only under the current control and exact retained publication head. */
export async function authorizePublication(input: SignedPublication, authority: PeerAuthority, previous: SignedPublication | null): Promise<void> {
  const publication = structuredClone(input), head = structuredClone(previous)
  await verifyPublicationManifest(publication, authority)
  check(publication.payload.controlRevision === authority.control.payload.revision && authority.grant(publication.payload.author)?.administrator === true,
    'PEER_PUBLICATION_CONTROL_CHANGED')
  if (head !== null) await verifyPublicationManifest(head, authority)
  check(publication.payload.previous === (head?.id ?? null) && publication.payload.revision === (head === null ? 0 : head.payload.revision + 1),
    'PEER_PUBLICATION_CONFLICT')
}

/** Publication references authenticate bytes; they never grant access to a provider. */
export async function verifyPublicationAsset(file: PublicationFile, input: Uint8Array): Promise<void> {
  object(file, ['path', 'hash', 'size', 'type']); path(file.path); hex(file.hash); uint(file.size, PUBLICATION_LIMITS.bytes)
  const bytes = input.slice()
  check(bytes.length === file.size && await bytesDigest(bytes) === file.hash, 'PEER_PUBLICATION_ASSET_MISMATCH')
}

export interface PublicationRegistry {
  read(): Promise<readonly SignedPublication[]>
  publish(publication: SignedPublication): Promise<SignedPublication>
}
interface PublicationState {
  readonly authority: AuthorityBundle
  readonly publications: readonly SignedPublication[]
}
interface VerifiedPublicationState {
  readonly authority: PeerAuthority
  readonly publications: readonly SignedPublication[]
}
const locks = new WeakMap<BytesStore, Map<string, Serial>>()
function publicationLock(store: BytesStore, key: string): Serial {
  let keys = locks.get(store)
  if (keys === undefined) { keys = new Map(); locks.set(store, keys) }
  let lock = keys.get(key)
  if (lock === undefined) { lock = new Serial(); keys.set(key, lock) }
  return lock
}

/** An exclusive control store publishes occasional metadata atomically; asset storage is a transport concern. */
export async function createPublicationRegistry(options: {
  readonly store: BytesStore
  readonly authority: () => Promise<AuthorityBundle>
  readonly requireExisting?: boolean
}): Promise<PublicationRegistry> {
  const store = options.store, readAuthority = options.authority
  const initial = await verifyAuthorityBundle(await readAuthority()), descriptor = initial.bundle.descriptor
  const key = `peer-generation/publications/${descriptor.payload.applicationId}`, lock = publicationLock(store, key)
  let learned = initial
  const encode = (state: VerifiedPublicationState): Uint8Array => {
    check(encodePeerValue(state.publications).length <= PUBLICATION_LIMITS.historyBytes, 'PEER_PUBLICATION_HISTORY_LIMIT')
    return encodePeerValue({ authority: state.authority.bundle, publications: state.publications })
  }
  const decode = async (bytes: Uint8Array): Promise<VerifiedPublicationState> => {
    const state = decodePeerValue<PublicationState>(bytes)
    object(state, ['authority', 'publications'])
    const verified = await verifyAuthorityBundle(state.authority, descriptor), values = state.publications
    check(isArray(values) && values.length <= PUBLICATION_LIMITS.revisions, 'PEER_PUBLICATION_HISTORY_LIMIT')
    check(encodePeerValue(values).length <= PUBLICATION_LIMITS.historyBytes, 'PEER_PUBLICATION_HISTORY_LIMIT')
    const operations = new Set<string>()
    for (const [index, publication] of values.entries()) {
      await verifyPublicationManifest(publication, verified)
      check(publication.payload.revision === index && publication.payload.previous === (values[index - 1]?.id ?? null), 'PEER_PUBLICATION_CHAIN_INVALID')
      check(!operations.has(publication.payload.operationId), 'PEER_PUBLICATION_OPERATION_REUSED'); operations.add(publication.payload.operationId)
    }
    return { authority: verified, publications: values }
  }
  const read = async (): Promise<VerifiedPublicationState> => {
    const bytes = await store.get(key); check(bytes !== null, 'PEER_PUBLICATION_STATE_MISSING')
    return decode(bytes)
  }
  const observe = async (state: VerifiedPublicationState, candidate?: PeerAuthority): Promise<VerifiedPublicationState> => {
    const verified = candidate ?? await verifyAuthorityBundle(await readAuthority(), descriptor)
    assertAuthorityExtension(state.authority, verified)
    assertAuthorityExtension(learned, verified)
    // Keep the owner fenced even if persisting this learned restriction loses its acknowledgment.
    learned = verified
    if (samePeerValue(state.authority.bundle, verified.bundle)) return state
    const next = { authority: verified, publications: state.publications }
    // The durable floor advances independently of whether a proposed release is authorized.
    await store.put(key, encode(next))
    return next
  }
  await lock.run(async () => {
    const bytes = await store.get(key)
    let state: VerifiedPublicationState
    if (bytes === null) {
      check(options.requireExisting !== true, 'PEER_PUBLICATION_STATE_MISSING')
      state = { authority: initial, publications: [] }
      await store.put(key, encode(state))
    } else state = await observe(await decode(bytes), initial)
    await observe(state)
  })
  return {
    read: () => lock.run(async () => structuredClone((await observe(await read())).publications)),
    async publish(input) {
      const publication = structuredClone(input)
      return lock.run(async () => {
        const state = await observe(await read()), verified = state.authority, values = state.publications
        await verifyPublicationManifest(publication, verified)
        const retry = values.find(value => value.payload.operationId === publication.payload.operationId)
        if (retry !== undefined) {
          check(samePeerValue(retry, publication), 'PEER_PUBLICATION_OPERATION_REUSED')
          return structuredClone(retry)
        }
        await authorizePublication(publication, verified, values.at(-1) ?? null)
        check(values.length < PUBLICATION_LIMITS.revisions, 'PEER_PUBLICATION_HISTORY_LIMIT')
        const publications = [...values, publication]
        check(encodePeerValue(publications).length <= PUBLICATION_LIMITS.historyBytes, 'PEER_PUBLICATION_HISTORY_LIMIT')
        // A newly learned restrictive control cannot be bypassed by slow preparation.
        const latest = await observe(state)
        await authorizePublication(publication, latest.authority, values.at(-1) ?? null)
        await store.put(key, encode({ authority: latest.authority, publications }))
        return structuredClone(publication)
      })
    },
  }
}
