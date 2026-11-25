export { parseApplicationInput, checkedApplicationInputSchema, validateApplicationDescription, applicationDescriptionDigest, type ApplicationInputSchema, type ApplicationInput, type ApplicationDescription } from './definition.js'
import type { BytesStore } from '@chronolog/records'
import { check, encodeRecord, decodeRecord, equalRecord, hex, recordDigest, signRecord, verifyRecord, type Signed, type SigningIdentity } from './codec.js'
export interface AdmissionScope { readonly id: string; readonly authorTimeAfterMs: bigint }
export type FinalityPolicy =
  | { readonly kind: 'none' }
  | { readonly kind: 'fixed-validator'; readonly validators: readonly string[]; readonly threshold: number; readonly scopes: readonly AdmissionScope[] }
  | { readonly kind: 'signed-frontier'; readonly signer: string; readonly scopes: readonly AdmissionScope[] }
export interface AppDescriptor {
  readonly applicationId: string
  readonly rootPrincipal: string
  readonly authorityPublicKey: string
  readonly executionManifestDigest: string
  readonly finalityPolicy: FinalityPolicy
}
export interface MemberGrant { readonly publicKey: string; readonly reader: boolean; readonly writer: boolean; readonly administrator: boolean; readonly publisher: boolean; readonly finalizer: boolean }
export interface Membership {
  readonly applicationId: string
  readonly revision: number
  /** Exclusive signed author-time activation floor; first revision starts at -1. */
  readonly authorTimeAfterMs: bigint
  readonly previous: string | null
  readonly members: readonly MemberGrant[]
  readonly epoch: number
  readonly epochKeyDigest: string
}
export type SignedAppDescriptor = Signed<AppDescriptor>
export type SignedMembership = Signed<Membership>
export interface AuthorityBundle { readonly descriptor: SignedAppDescriptor; readonly memberships: readonly SignedMembership[] }
export interface AuthorityProvider {
  readonly descriptor: AppDescriptor
  readonly descriptorId: string
  readonly currentMembershipId: string
  readonly currentMembership: Membership
  bundle(): AuthorityBundle
  grant(publicKey: string, membershipId?: string): MemberGrant | null
  hasMembership(id: string): boolean
  membership(id: string): Membership | null
  epochKey(epoch: number): Uint8Array | null
  installEpochKey(epoch: number, key: Uint8Array): Promise<void>
  merge(bundle: AuthorityBundle): Promise<void>
  subscribe(listener: () => void): () => void
}
function exactRecord(value: unknown, keys: readonly string[], code: string): asserts value is Record<string, unknown> {
  check(value !== null && typeof value === 'object' && !Array.isArray(value) && [Object.prototype, null].includes(Object.getPrototypeOf(value) as object | null), code)
  check(Reflect.ownKeys(value).length === keys.length && keys.every(key => { const field = Object.getOwnPropertyDescriptor(value, key); return field !== undefined && 'value' in field }), code)
}
/** Portable pre-owner validation; no fabricated data-root descriptor or key is needed. */
export function validateFinalityPolicy(input: unknown): FinalityPolicy {
  check(input !== null && typeof input === 'object', 'FINALITY_POLICY_UNSUPPORTED')
  const kind: unknown = Object.getOwnPropertyDescriptor(input, 'kind')?.value
  if (kind === 'none') { exactRecord(input, ['kind'], 'FINALITY_POLICY_FIELDS_INVALID'); return { kind: 'none' } }
  check(kind === 'fixed-validator' || kind === 'signed-frontier', 'FINALITY_POLICY_UNSUPPORTED')
  exactRecord(input, kind === 'fixed-validator' ? ['kind', 'validators', 'threshold', 'scopes'] : ['kind', 'signer', 'scopes'], 'FINALITY_POLICY_FIELDS_INVALID')
  check(Array.isArray(input.scopes) && input.scopes.length > 0 && input.scopes.length <= 4096, 'FINALITY_SCOPE_INVALID')
  const scopes: AdmissionScope[] = [], ids = new Set<string>(); let bound = -1n
  for (const value of input.scopes as readonly unknown[]) {
    exactRecord(value, ['id', 'authorTimeAfterMs'], 'FINALITY_SCOPE_INVALID'); hex(value.id)
    check(typeof value.authorTimeAfterMs === 'bigint' && value.authorTimeAfterMs >= bound && value.authorTimeAfterMs <= (1n << 63n) - 1n && (scopes.length > 0 || value.authorTimeAfterMs === -1n) && !ids.has(value.id), 'FINALITY_SCOPE_INVALID')
    scopes.push({ id: value.id, authorTimeAfterMs: value.authorTimeAfterMs }); ids.add(value.id); bound = value.authorTimeAfterMs
  }
  if (kind === 'signed-frontier') { hex(input.signer); return { kind, signer: input.signer, scopes } }
  check(Array.isArray(input.validators) && input.validators.length > 0 && input.validators.length <= 4096, 'FINALITY_VALIDATORS_INVALID')
  const validators: string[] = []
  for (const key of input.validators as readonly unknown[]) { hex(key); validators.push(key) }
  check(new Set(validators).size === validators.length && typeof input.threshold === 'number' && Number.isSafeInteger(input.threshold) && input.threshold > 0 && input.threshold <= validators.length, 'FINALITY_VALIDATORS_INVALID')
  return { kind, validators, threshold: input.threshold, scopes }
}
export function validateDescriptor(value: AppDescriptor): void {
  exactRecord(value, ['applicationId', 'rootPrincipal', 'authorityPublicKey', 'executionManifestDigest', 'finalityPolicy'], 'AUTHORITY_DESCRIPTOR_FIELDS_INVALID')
  hex(value.applicationId); hex(value.rootPrincipal); hex(value.authorityPublicKey); hex(value.executionManifestDigest)
  validateFinalityPolicy(value.finalityPolicy)
}
export async function signAppDescriptor(descriptor: AppDescriptor, signer: SigningIdentity): Promise<SignedAppDescriptor> { validateDescriptor(descriptor); check(signer.publicKey === descriptor.authorityPublicKey, 'AUTHORITY_SIGNER_MISMATCH'); return signRecord('descriptor', descriptor, signer) }
export async function signMembership(membership: Membership, signer: SigningIdentity): Promise<SignedMembership> { return signRecord('membership', membership, signer) }
export async function verifyAuthorityBundle(input: AuthorityBundle, pinned?: SignedAppDescriptor): Promise<void> {
  const bundle = structuredClone(input), descriptor = bundle.descriptor.payload
  validateDescriptor(descriptor); await verifyRecord('descriptor', bundle.descriptor, descriptor.authorityPublicKey)
  check(pinned === undefined || equalRecord(pinned, bundle.descriptor), 'AUTHORITY_DESCRIPTOR_MISMATCH')
  check(bundle.memberships.length > 0 && bundle.memberships.length <= 4096, 'AUTHORITY_MEMBERSHIP_LIMIT')
  let previous: string | null = null
  for (const [revision, signed] of bundle.memberships.entries()) {
    const value = signed.payload
    check(value.applicationId === descriptor.applicationId && value.revision === revision && value.previous === previous && Number.isSafeInteger(value.epoch) && value.epoch >= 0, 'AUTHORITY_CHAIN_INVALID')
    hex(value.epochKeyDigest)
    const priorEpoch = bundle.memberships.slice(0, revision).find(item => item.payload.epoch === value.epoch)
    check(priorEpoch === undefined || priorEpoch.payload.epochKeyDigest === value.epochKeyDigest, 'AUTHORITY_EPOCH_COMMITMENT_CHANGED')
    check(typeof value.authorTimeAfterMs === 'bigint' && (revision === 0 ? value.authorTimeAfterMs === -1n : value.authorTimeAfterMs > bundle.memberships[revision - 1]!.payload.authorTimeAfterMs), 'AUTHORITY_ACTIVATION_INVALID')
    check(value.members.length <= 4096 && new Set(value.members.map(member => member.publicKey)).size === value.members.length, 'AUTHORITY_MEMBERS_INVALID')
    for (const member of value.members) { hex(member.publicKey); for (const flag of [member.reader, member.writer, member.publisher, member.administrator, member.finalizer]) check(typeof flag === 'boolean', 'AUTHORITY_MEMBERS_INVALID') }
    if (revision === 0) check(value.members.some(member => member.publicKey === descriptor.rootPrincipal), 'AUTHORITY_ROOT_MISSING')
    if (signed.signer !== descriptor.authorityPublicKey) check(bundle.memberships[revision - 1]?.payload.members.some(member => member.publicKey === signed.signer && member.administrator), 'AUTHORITY_ADMIN_REQUIRED')
    await verifyRecord('membership', signed); previous = await recordDigest(signed)
  }
}
export function writerAuthorizedAt(authority: Pick<AuthorityProvider, 'membership' | 'bundle'>, publicKey: string, membershipId: string, authorTimestampMs: bigint, throughRevision = Number.MAX_SAFE_INTEGER): boolean | null {
  const base = authority.membership(membershipId)
  if (base === null) return null
  if (authorTimestampMs <= base.authorTimeAfterMs || base.members.find(member => member.publicKey === publicKey)?.writer !== true) return false
  // An unchanged grant is valid for an offline cached certificate. A revoke/regrant gap is not.
  for (const successor of authority.bundle().memberships.slice(base.revision + 1)) {
    if (successor.payload.revision > throughRevision || authorTimestampMs <= successor.payload.authorTimeAfterMs) break
    if (successor.payload.members.find(member => member.publicKey === publicKey)?.writer !== true) return false
  }
  return true
}
export function finalizerAuthorizedAt(authority: Pick<AuthorityProvider, 'membership' | 'bundle'>, publicKey: string, authorityHead: string, throughMs: bigint): boolean | null {
  const head = authority.membership(authorityHead)
  if (head === null) return null
  if (head.members.find(member => member.publicKey === publicKey)?.finalizer !== true) return false
  for (const successor of authority.bundle().memberships.slice(head.revision + 1)) {
    if (throughMs <= successor.payload.authorTimeAfterMs) break
    if (successor.payload.members.find(member => member.publicKey === publicKey)?.finalizer !== true) return false
  }
  return true
}
export async function epochKeyCommitment(applicationId: string, epoch: number, key: Uint8Array): Promise<string> { hex(applicationId); check(Number.isSafeInteger(epoch) && epoch >= 0 && key.length === 32, 'AUTHORITY_EPOCH_KEY_INVALID'); return recordDigest(['epoch-key', applicationId, epoch, key]) }
const owners = new WeakSet<BytesStore>()
/** Local authority and keys reopen before any optional remote refresh; no remote fetch belongs to this port. */
export async function createAuthorityProvider(options: { readonly store: BytesStore; readonly bundle?: AuthorityBundle; readonly applicationId?: string; readonly epochKeys?: ReadonlyMap<number, Uint8Array> }): Promise<AuthorityProvider> {
  check(!owners.has(options.store), 'AUTHORITY_STORE_BUSY'); owners.add(options.store)
  try {
    const applicationId = options.bundle?.descriptor.payload.applicationId ?? options.applicationId
    hex(applicationId)
    const key = `authority/${applicationId}`, cached = await options.store.get(key)
    let bundle = cached === null ? options.bundle : decodeRecord<AuthorityBundle>(cached)
    check(bundle !== undefined, 'AUTHORITY_CACHE_MISSING'); await verifyAuthorityBundle(bundle)
    if (options.bundle !== undefined && cached !== null) {
      await verifyAuthorityBundle(options.bundle, bundle.descriptor)
      for (let i = 0; i < Math.min(bundle.memberships.length, options.bundle.memberships.length); i++) check(equalRecord(bundle.memberships[i], options.bundle.memberships[i]), 'AUTHORITY_CHAIN_FORK')
      if (options.bundle.memberships.length > bundle.memberships.length) bundle = structuredClone(options.bundle)
    }
    await options.store.put(key, encodeRecord(bundle))
    const keys = new Map<number, Uint8Array>(), listeners = new Set<() => void>()
    const keyBytes = await options.store.get(`${key}/epoch-keys`)
    if (keyBytes !== null) for (const [epoch, bytes] of decodeRecord<readonly (readonly [number, Uint8Array])[]>(keyBytes)) keys.set(epoch, bytes)
    const validateKey = async (epoch: number, bytes: Uint8Array): Promise<void> => { check(bytes instanceof Uint8Array && bytes.length === 32 && Number.isSafeInteger(epoch) && epoch >= 0, 'AUTHORITY_EPOCH_KEY_INVALID'); const membership = bundle!.memberships.find(item => item.payload.epoch === epoch); check(membership !== undefined && membership.payload.epochKeyDigest === await epochKeyCommitment(applicationId, epoch, bytes), 'AUTHORITY_EPOCH_KEY_COMMITMENT_MISMATCH') }
    for (const [epoch, bytes] of keys) await validateKey(epoch, bytes)
    const persistKeys = async (): Promise<void> => { await options.store.put(`${key}/epoch-keys`, encodeRecord([...keys])) }
    for (const [epoch, bytes] of options.epochKeys ?? []) { await validateKey(epoch, bytes); check(!keys.has(epoch) || equalRecord(keys.get(epoch), bytes), 'AUTHORITY_EPOCH_KEY_CONFLICT'); keys.set(epoch, bytes.slice()) }
    if (options.epochKeys !== undefined) await persistKeys()
    const ids = new Map<string, Membership>()
    const index = async (): Promise<void> => { ids.clear(); for (const signed of bundle!.memberships) ids.set(await recordDigest(signed), signed.payload) }
    await index(); if (cached === null) await options.store.put(key, encodeRecord(bundle))
    let tail: Promise<void> = Promise.resolve()
    const provider: AuthorityProvider = {
      get descriptor() { return structuredClone(bundle!.descriptor.payload) }, descriptorId: await recordDigest(bundle.descriptor),
      get currentMembershipId() { return [...ids.keys()].at(-1)! }, get currentMembership() { return structuredClone(bundle!.memberships.at(-1)!.payload) },
      bundle: () => structuredClone(bundle!),
      grant: (publicKey, id) => structuredClone((id === undefined ? bundle!.memberships.at(-1)!.payload : ids.get(id))?.members.find(member => member.publicKey === publicKey) ?? null),
      hasMembership: id => ids.has(id), membership: id => structuredClone(ids.get(id) ?? null), epochKey: epoch => keys.get(epoch)?.slice() ?? null,
      installEpochKey(epoch, input) {
        const bytes = input.slice()
        const task = tail.then(async () => {
          await validateKey(epoch, bytes); check(!keys.has(epoch) || equalRecord(keys.get(epoch), bytes), 'AUTHORITY_EPOCH_KEY_CONFLICT')
          const next = new Map(keys); next.set(epoch, bytes)
          await options.store.put(`${key}/epoch-keys`, encodeRecord([...next])); keys.set(epoch, bytes)
          for (const listener of listeners) { try { listener() } catch { /* Durable keys cannot be undone by observers. */ } }
        }); tail = task.catch(() => undefined); return task
      },
      merge(input) {
        const captured = structuredClone(input)
        const task = tail.then(async () => {
          await verifyAuthorityBundle(captured, bundle!.descriptor)
          for (let i = 0; i < Math.min(captured.memberships.length, bundle!.memberships.length); i++) check(equalRecord(captured.memberships[i], bundle!.memberships[i]), 'AUTHORITY_CHAIN_FORK')
          if (captured.memberships.length <= bundle!.memberships.length) return
          await options.store.put(key, encodeRecord(captured)); bundle = captured; await index()
          for (const listener of listeners) { try { listener() } catch { /* Durable authority cannot be undone by observers. */ } }
        }); tail = task.catch(() => undefined); return task
      },
      subscribe(listener) { listeners.add(listener); return () => { listeners.delete(listener) } },
    }
    if (options.bundle !== undefined && cached !== null) await provider.merge(options.bundle)
    return provider
  } finally { owners.delete(options.store) }
}
export interface EnrollmentRequest { readonly applicationId: string; readonly publicKey: string; readonly challenge: string; readonly epoch: number; readonly epochKeyDigest: string }
export type SignedEnrollmentRequest = Signed<EnrollmentRequest>
export async function signEnrollmentRequest(request: EnrollmentRequest, identity: SigningIdentity): Promise<SignedEnrollmentRequest> { hex(request.applicationId); hex(request.publicKey); hex(request.epochKeyDigest); check(Number.isSafeInteger(request.epoch) && request.epoch >= 0, 'ENROLLMENT_EPOCH_INVALID'); check(request.publicKey === identity.publicKey && request.challenge.length > 0 && request.challenge.length <= 512, 'ENROLLMENT_REQUEST_INVALID'); return signRecord('enrollment', request, identity) }
export async function verifyEnrollmentRequest(request: SignedEnrollmentRequest): Promise<void> { hex(request.payload.applicationId); hex(request.payload.publicKey); hex(request.payload.epochKeyDigest); check(Number.isSafeInteger(request.payload.epoch) && request.payload.epoch >= 0, 'ENROLLMENT_EPOCH_INVALID'); check(typeof request.payload.challenge === 'string' && request.payload.challenge.length > 0 && request.payload.challenge.length <= 512, 'ENROLLMENT_REQUEST_INVALID'); await verifyRecord('enrollment', request, request.payload.publicKey) }
