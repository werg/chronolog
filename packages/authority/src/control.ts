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
/** `wrapKey` is the member's long-lived X25519 key-wrap public key (hex), or null for a key that never receives data keys. */
export interface MemberGrant { readonly publicKey: string; readonly wrapKey: string | null; readonly reader: boolean; readonly writer: boolean; readonly administrator: boolean; readonly publisher: boolean; readonly finalizer: boolean }
/**
 * Signed admission policy carried by every membership revision. `hostKey` pins the
 * host's Ed25519 attestation key; `accounts` names the host account principals
 * (`<accountId>` or `email:<address>`) whose attested devices any reader member may
 * admit in `attested` mode with exactly `grant`. `strict` requires an administrator.
 */
export interface AdmissionPolicy {
  readonly mode: 'attested' | 'strict'
  readonly hostKey: string
  readonly accounts: readonly string[]
  readonly grant: { readonly reader: boolean; readonly writer: boolean }
}
/** A host statement that an authenticated account proved possession of a device or agent key for one page. It is evidence, never membership. */
export interface HostAttestation {
  readonly subject: 'device' | 'agent'
  readonly pageId: string
  readonly applicationId: string
  readonly accountId: string
  readonly email: string | null
  readonly publicKey: string
  readonly wrapKey: string
  readonly label: string
  /** The redeemed invite, or null for the owner-account path. */
  readonly inviteId: string | null
  readonly issuedAt: bigint
  readonly expiresAt: bigint
  readonly nonce: string
}
export type SignedHostAttestation = Signed<HostAttestation>
export type InviteBinding = { readonly kind: 'email'; readonly email: string } | { readonly kind: 'open' } | { readonly kind: 'public'; readonly max: number | null }
export type InviteRole = 'reader' | 'writer' | 'admin'
/** An administrator-signed invitation. Only `secretDigest` (SHA-256 hex of the link secret) is in state; the secret travels in the link fragment. */
export interface PageInvite { readonly inviteId: string; readonly role: InviteRole; readonly binding: InviteBinding; readonly expiresAt: bigint; readonly secretDigest: string; readonly revoked: boolean }
/**
 * Evidence for one member added in a revision: `attested` (owner-account device,
 * any reader in attested mode), `invited` (redeemed invite, any reader in attested
 * mode) or `approved` (administrator decision on an attested key).
 */
export interface MemberAdmission { readonly publicKey: string; readonly via: 'attested' | 'invited' | 'approved'; readonly attestation: SignedHostAttestation }
export function inviteGrant(role: InviteRole): { readonly reader: boolean; readonly writer: boolean; readonly administrator: boolean } { return { reader: true, writer: role !== 'reader', administrator: role === 'admin' } }
export interface Membership {
  readonly applicationId: string
  readonly revision: number
  /** Exclusive signed author-time activation floor; first revision starts at -1. */
  readonly authorTimeAfterMs: bigint
  readonly previous: string | null
  readonly members: readonly MemberGrant[]
  readonly epoch: number
  readonly epochKeyDigest: string
  readonly admission: AdmissionPolicy
  /** Admission evidence for members first added by this revision; empty for genesis and administrative changes without attestation. */
  readonly admitted: readonly MemberAdmission[]
  /** Every invite still recorded, including revoked ones; changing it requires an administrator. */
  readonly invites: readonly PageInvite[]
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
const isList = (value: unknown): boolean => Array.isArray(value)
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
export function validateAdmissionPolicy(input: unknown): AdmissionPolicy {
  exactRecord(input, ['mode', 'hostKey', 'accounts', 'grant'], 'ADMISSION_POLICY_INVALID')
  check(input.mode === 'attested' || input.mode === 'strict', 'ADMISSION_POLICY_INVALID'); hex(input.hostKey)
  check(Array.isArray(input.accounts) && input.accounts.length <= 64 && (input.accounts as unknown[]).every(value => typeof value === 'string' && value.length > 0 && value.length <= 320) && new Set(input.accounts).size === input.accounts.length, 'ADMISSION_POLICY_INVALID')
  exactRecord(input.grant, ['reader', 'writer'], 'ADMISSION_POLICY_INVALID')
  check(typeof input.grant.reader === 'boolean' && typeof input.grant.writer === 'boolean', 'ADMISSION_POLICY_INVALID')
  return { mode: input.mode, hostKey: input.hostKey, accounts: [...input.accounts as string[]], grant: { reader: input.grant.reader, writer: input.grant.writer } }
}
export function validateInvites(input: unknown): readonly PageInvite[] {
  check(Array.isArray(input) && input.length <= 256, 'INVITE_INVALID')
  const ids = new Set<string>()
  for (const invite of input as unknown[]) {
    exactRecord(invite, ['inviteId', 'role', 'binding', 'expiresAt', 'secretDigest', 'revoked'], 'INVITE_INVALID')
    hex(invite.inviteId, 16); hex(invite.secretDigest)
    check(!ids.has(invite.inviteId) && ['reader', 'writer', 'admin'].includes(invite.role as string) && typeof invite.expiresAt === 'bigint' && invite.expiresAt > 0n && typeof invite.revoked === 'boolean', 'INVITE_INVALID'); ids.add(invite.inviteId)
    const binding = invite.binding as Record<string, unknown>
    check(binding !== null && typeof binding === 'object', 'INVITE_INVALID')
    if (binding.kind === 'email') { exactRecord(binding, ['kind', 'email'], 'INVITE_INVALID'); check(typeof binding.email === 'string' && binding.email.length <= 254 && /^[^\s@]+@[^\s@]+$/u.test(binding.email) && binding.email === binding.email.toLowerCase(), 'INVITE_INVALID') }
    else if (binding.kind === 'open') exactRecord(binding, ['kind'], 'INVITE_INVALID')
    else { check(binding.kind === 'public', 'INVITE_INVALID'); exactRecord(binding, ['kind', 'max'], 'INVITE_INVALID'); check(binding.max === null || typeof binding.max === 'number' && Number.isSafeInteger(binding.max) && binding.max > 0 && binding.max <= 100_000, 'INVITE_INVALID') }
  }
  return input as readonly PageInvite[]
}
/** Number of members admitted through one invite in a membership chain. */
export function inviteRedemptions(memberships: readonly SignedMembership[], inviteId: string): number { return memberships.reduce((total, item) => total + item.payload.admitted.filter(admission => admission.via === 'invited' && admission.attestation.payload.inviteId === inviteId).length, 0) }
/** Whether an invite admits this attestation at a signed activation time, excluding the double-spend check. */
export function inviteAdmits(invite: PageInvite | undefined, attestation: HostAttestation, activation: bigint): invite is PageInvite {
  return invite !== undefined && !invite.revoked && activation < invite.expiresAt && (invite.binding.kind !== 'email' || attestation.email === invite.binding.email)
}
export function inviteCapacity(invite: PageInvite): number { return invite.binding.kind === 'public' ? invite.binding.max ?? Number.MAX_SAFE_INTEGER : 1 }
export async function signHostAttestation(value: HostAttestation, host: SigningIdentity): Promise<SignedHostAttestation> { validateAttestation(value); return signRecord('host-attestation', value, host) }
function validateAttestation(value: HostAttestation): void {
  exactRecord(value, ['subject', 'pageId', 'applicationId', 'accountId', 'email', 'publicKey', 'wrapKey', 'label', 'inviteId', 'issuedAt', 'expiresAt', 'nonce'], 'ATTESTATION_INVALID')
  check(value.inviteId === null || typeof value.inviteId === 'string' && /^[0-9a-f]{32}$/u.test(value.inviteId), 'ATTESTATION_INVALID')
  check((value.subject === 'device' || value.subject === 'agent') && typeof value.pageId === 'string' && /^[a-z2-7]{1,64}$/u.test(value.pageId) && typeof value.accountId === 'string' && value.accountId.length > 0 && value.accountId.length <= 128 &&
    (value.email === null || typeof value.email === 'string' && value.email.length <= 254 && value.email === value.email.toLowerCase()) && typeof value.label === 'string' && value.label.length <= 128 &&
    typeof value.issuedAt === 'bigint' && typeof value.expiresAt === 'bigint' && value.issuedAt >= 0n && value.expiresAt > value.issuedAt && value.expiresAt - value.issuedAt <= 86_400_000n, 'ATTESTATION_INVALID')
  hex(value.applicationId); hex(value.publicKey); hex(value.wrapKey); hex(value.nonce)
}
/** Verify a host attestation's signature against the pinned host key and its page/application scope; freshness is the caller's decision. */
export async function verifyHostAttestation(value: SignedHostAttestation, expected: { readonly hostKey: string; readonly applicationId: string; readonly pageId?: string }): Promise<HostAttestation> {
  validateAttestation(value.payload); await verifyRecord('host-attestation', value, expected.hostKey)
  check(value.payload.applicationId === expected.applicationId && (expected.pageId === undefined || value.payload.pageId === expected.pageId), 'ATTESTATION_SCOPE_MISMATCH')
  return value.payload
}
/** True when the policy authorizes the attested account for automatic admission. */
export function attestedAccountAuthorized(policy: AdmissionPolicy, attestation: HostAttestation): boolean {
  return policy.accounts.includes(attestation.accountId) || attestation.email !== null && policy.accounts.includes(`email:${attestation.email}`)
}
function sameGrant(a: MemberGrant, b: MemberGrant): boolean { return a.publicKey === b.publicKey && a.wrapKey === b.wrapKey && a.reader === b.reader && a.writer === b.writer && a.administrator === b.administrator && a.publisher === b.publisher && a.finalizer === b.finalizer }
export async function verifyAuthorityBundle(input: AuthorityBundle, pinned?: SignedAppDescriptor): Promise<void> {
  const bundle = structuredClone(input), descriptor = bundle.descriptor.payload
  validateDescriptor(descriptor); await verifyRecord('descriptor', bundle.descriptor, descriptor.authorityPublicKey)
  check(pinned === undefined || equalRecord(pinned, bundle.descriptor), 'AUTHORITY_DESCRIPTOR_MISMATCH')
  check(bundle.memberships.length > 0 && bundle.memberships.length <= 4096, 'AUTHORITY_MEMBERSHIP_LIMIT')
  let previous: string | null = null
  const nonces = new Set<string>()
  for (const [revision, signed] of bundle.memberships.entries()) {
    const value = signed.payload, prior = revision === 0 ? null : bundle.memberships[revision - 1]!.payload
    exactRecord(value, ['applicationId', 'revision', 'authorTimeAfterMs', 'previous', 'members', 'epoch', 'epochKeyDigest', 'admission', 'admitted', 'invites'], 'AUTHORITY_CHAIN_INVALID')
    check(value.applicationId === descriptor.applicationId && value.revision === revision && value.previous === previous && Number.isSafeInteger(value.epoch) && value.epoch >= 0, 'AUTHORITY_CHAIN_INVALID')
    hex(value.epochKeyDigest); validateAdmissionPolicy(value.admission); validateInvites(value.invites)
    const priorEpoch = bundle.memberships.slice(0, revision).find(item => item.payload.epoch === value.epoch)
    check(priorEpoch === undefined || priorEpoch.payload.epochKeyDigest === value.epochKeyDigest, 'AUTHORITY_EPOCH_COMMITMENT_CHANGED')
    check(typeof value.authorTimeAfterMs === 'bigint' && (prior === null ? value.authorTimeAfterMs === -1n : value.authorTimeAfterMs > prior.authorTimeAfterMs), 'AUTHORITY_ACTIVATION_INVALID')
    check(isList(value.members) && value.members.length <= 4096 && new Set(value.members.map(member => member.publicKey)).size === value.members.length, 'AUTHORITY_MEMBERS_INVALID')
    for (const member of value.members) {
      exactRecord(member, ['publicKey', 'wrapKey', 'reader', 'writer', 'administrator', 'publisher', 'finalizer'], 'AUTHORITY_MEMBERS_INVALID')
      hex(member.publicKey); if (member.wrapKey !== null) hex(member.wrapKey)
      for (const flag of [member.reader, member.writer, member.publisher, member.administrator, member.finalizer]) check(typeof flag === 'boolean', 'AUTHORITY_MEMBERS_INVALID')
    }
    if (prior === null) check(value.members.some(member => member.publicKey === descriptor.rootPrincipal) && isList(value.admitted) && value.admitted.length === 0, 'AUTHORITY_ROOT_MISSING')
    // Admission evidence is verified against the policy in force before this revision.
    check(isList(value.admitted) && value.admitted.length <= 64, 'AUTHORITY_ADMISSION_INVALID')
    const policy = prior?.admission ?? value.admission, added = new Set<string>()
    for (const admission of value.admitted) {
      exactRecord(admission, ['publicKey', 'via', 'attestation'], 'AUTHORITY_ADMISSION_INVALID')
      check(admission.via === 'attested' || admission.via === 'invited' || admission.via === 'approved', 'AUTHORITY_ADMISSION_INVALID')
      const attestation = await verifyHostAttestation(admission.attestation, { hostKey: policy.hostKey, applicationId: descriptor.applicationId })
      const member = value.members.find(item => item.publicKey === admission.publicKey)
      check(attestation.publicKey === admission.publicKey && member !== undefined && member.wrapKey === attestation.wrapKey && !added.has(admission.publicKey) && !prior?.members.some(item => item.publicKey === admission.publicKey), 'AUTHORITY_ADMISSION_INVALID')
      // Deterministic freshness: the signed activation floor lies inside the host attestation window.
      check(attestation.issuedAt <= value.authorTimeAfterMs && value.authorTimeAfterMs < attestation.expiresAt, 'AUTHORITY_ADMISSION_EXPIRED')
      check(!nonces.has(attestation.nonce), 'AUTHORITY_ADMISSION_REPLAYED'); nonces.add(attestation.nonce); added.add(admission.publicKey)
      if (admission.via === 'attested') check(attestation.inviteId === null && attestedAccountAuthorized(policy, attestation), 'AUTHORITY_ADMISSION_ACCOUNT_FORBIDDEN')
      if (admission.via === 'invited') check(attestation.inviteId !== null && inviteAdmits(prior?.invites.find(item => item.inviteId === attestation.inviteId), attestation, value.authorTimeAfterMs), 'AUTHORITY_INVITE_INVALID')
    }
    if (prior !== null && signed.signer !== descriptor.authorityPublicKey && !prior.members.some(member => member.publicKey === signed.signer && member.administrator)) {
      // A non-administrator reader may only append attested or invited members with
      // exactly the grant the signed policy or invite assigns, within invite capacity.
      const grantFor = (item: MemberAdmission): { reader: boolean; writer: boolean; administrator: boolean } => {
        if (item.via === 'attested') return { ...prior.admission.grant, administrator: false }
        const invite = prior.invites.find(entry => entry.inviteId === item.attestation.payload.inviteId)!
        check(inviteRedemptions(bundle.memberships.slice(0, revision + 1), invite.inviteId) <= inviteCapacity(invite), 'AUTHORITY_INVITE_EXHAUSTED')
        return inviteGrant(invite.role)
      }
      // A removed key never re-enters automatically: re-admission is an administrator decision.
      const everMember = new Set(bundle.memberships.slice(0, revision).flatMap(item => item.payload.members.map(member => member.publicKey)))
      check(prior.members.some(member => member.publicKey === signed.signer && member.reader) && prior.admission.mode === 'attested' && value.admitted.length > 0 && value.admitted.every(item => item.via !== 'approved' && !everMember.has(item.publicKey)) &&
        value.epoch === prior.epoch && equalRecord(value.admission, prior.admission) && equalRecord(value.invites, prior.invites) && value.members.length === prior.members.length + value.admitted.length &&
        prior.members.every((member, index) => sameGrant(member, value.members[index]!)) &&
        value.admitted.every((item, index) => sameGrant(value.members[prior.members.length + index]!, { publicKey: item.publicKey, wrapKey: item.attestation.payload.wrapKey, ...grantFor(item), publisher: false, finalizer: false })), 'AUTHORITY_ADMIN_REQUIRED')
    }
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
/** Device-key proof for one page: binds the signing key, its key-wrap key and the host challenge. */
export interface EnrollmentRequest { readonly applicationId: string; readonly publicKey: string; readonly wrapKey: string; readonly challenge: string }
export type SignedEnrollmentRequest = Signed<EnrollmentRequest>
function validateEnrollment(request: EnrollmentRequest): void { exactRecord(request, ['applicationId', 'publicKey', 'wrapKey', 'challenge'], 'ENROLLMENT_REQUEST_INVALID'); hex(request.applicationId); hex(request.publicKey); hex(request.wrapKey); check(typeof request.challenge === 'string' && request.challenge.length > 0 && request.challenge.length <= 512, 'ENROLLMENT_REQUEST_INVALID') }
export async function signEnrollmentRequest(request: EnrollmentRequest, identity: SigningIdentity): Promise<SignedEnrollmentRequest> { validateEnrollment(request); check(request.publicKey === identity.publicKey, 'ENROLLMENT_REQUEST_INVALID'); return signRecord('enrollment', request, identity) }
export async function verifyEnrollmentRequest(request: SignedEnrollmentRequest): Promise<void> { validateEnrollment(request.payload); await verifyRecord('enrollment', request, request.payload.publicKey) }
