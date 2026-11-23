import type { BytesStore } from '@chronolog/records'
import { DOMAINS } from '@chronolog/protocol'
import {
  boundedText, bytesToHex, check, isArray, decodePeerValue, encodePeerValue, hex, object, peerDigest,
  samePeerValue, Serial, signPeerValue, uint, verifyPeerValue,
} from './codec.js'
import {
  PEER_GENERATION_POLICY, PEER_GENERATION_PROFILE,
  type ApplicationDescriptor, type AuthorityBundle, type ControlRevision, type GenerationRecord,
  type HistoryPoint, type OrderReceipt, type PeerGrant, type PeerIdentity, type PrefixProof, type SignedApplicationDescriptor, type SignedControlRevision,
  type SignedGeneration, type SignedTransitionRequest, type TransitionRequest,
} from './control-types.js'

export * from './control-types.js'
export * from './definition.js'
export * from './schema.js'
export * from './participant.js'
export * from './publication.js'
export { createPeerIdentity, exportPeerIdentity, importPeerIdentity, PeerGenerationError, encodePeerValue, decodePeerValue, peerDigest, bytesDigest } from './codec.js'

/** Monotonic learned authority: a signed older state or a divergent chain cannot replace it. */
export function assertAuthorityExtension(previous: PeerAuthority, next: PeerAuthority): void {
  const old = previous.bundle, current = next.bundle
  check(samePeerValue(old.descriptor, current.descriptor), 'PEER_DESCRIPTOR_MISMATCH')
  check(current.generations.length >= old.generations.length && current.controls.length >= old.controls.length, 'PEER_AUTHORITY_REGRESSION')
  for (let index = 0; index < old.generations.length; index++) check(samePeerValue(old.generations[index], current.generations[index]), 'PEER_CONTROL_EQUIVOCATION')
  for (let index = 0; index < old.controls.length; index++) check(samePeerValue(old.controls[index], current.controls[index]), 'PEER_CONTROL_EQUIVOCATION')
}

function scope(value: { applicationId: string; profile: string; policy?: string }, descriptor: ApplicationDescriptor): void {
  check(value.applicationId === descriptor.applicationId && value.profile === PEER_GENERATION_PROFILE &&
    (value.policy === undefined || value.policy === descriptor.policy), 'PEER_SCOPE_MISMATCH')
}
function validateDescriptor(value: ApplicationDescriptor): void {
  object(value, ['applicationId', 'historyId', 'profile', 'policy', 'controlPublicKey', 'schemaAdministrator', 'executionManifestDigest', 'definitionDigest', 'schemaDigest'])
  hex(value.applicationId); boundedText(value.historyId, 128); hex(value.controlPublicKey); hex(value.schemaAdministrator)
  hex(value.executionManifestDigest); hex(value.definitionDigest)
  if (value.schemaDigest !== null) hex(value.schemaDigest)
  check(value.profile === PEER_GENERATION_PROFILE && value.policy === PEER_GENERATION_POLICY, 'PEER_PROFILE_UNSUPPORTED')
}
export function validateHistoryPoint(point: HistoryPoint): void {
  object(point, ['generation', 'sequence', 'root']); hex(point.generation); uint(point.sequence); hex(point.root)
}
function validateControl(value: ControlRevision): void {
  object(value, ['applicationId', 'profile', 'policy', 'revision', 'previous', 'epoch', 'keyDigest', 'grants', 'recoveryFloor'])
  hex(value.applicationId); uint(value.revision); uint(value.epoch); hex(value.keyDigest)
  if (value.previous !== null) hex(value.previous)
  check(isArray(value.grants) && value.grants.length > 0 && value.grants.length <= 1024, 'PEER_GRANTS_INVALID')
  const keys = new Set<string>()
  for (const grant of value.grants) {
    const fields = ['publicKey', 'reader', 'writer', 'coordinator', 'recovery', 'administrator', 'publisher', 'dataRole']
    if (grant?.relay !== undefined) { fields.push('relay'); check(grant.relay === true && grant.reader, 'PEER_GRANT_INVALID') }
    object(grant, fields); hex(grant.publicKey)
    for (const key of ['reader', 'writer', 'coordinator', 'recovery', 'administrator', 'publisher'] as const) check(typeof grant[key] === 'boolean', 'PEER_GRANT_INVALID')
    check(!keys.has(grant.publicKey), 'PEER_DUPLICATE_GRANT'); keys.add(grant.publicKey)
    check(!grant.coordinator || grant.reader, 'PEER_COORDINATOR_MUST_READ')
    check(grant.dataRole === null || grant.dataRole === 'member' || grant.dataRole === 'admin', 'PEER_DATA_ROLE_INVALID')
  }
  check(value.grants.some(grant => grant.administrator), 'PEER_ADMINISTRATOR_REQUIRED')
  if (value.recoveryFloor !== null) validateHistoryPoint(value.recoveryFloor)
}
function validateRequest(value: TransitionRequest): void {
  object(value, ['applicationId', 'profile', 'policy', 'transitionId', 'expectedGeneration', 'coordinator', 'requester', 'controlRevision', 'reason', 'base'])
  hex(value.applicationId); boundedText(value.transitionId, 128); hex(value.coordinator); hex(value.requester); uint(value.controlRevision)
  if (value.expectedGeneration !== null) hex(value.expectedGeneration)
  check(['create', 'handover', 'takeover', 'control-change'].includes(value.reason), 'PEER_TRANSITION_REASON_INVALID')
  if (value.base !== null) {
    object(value.base, ['point', 'receipt', 'bridge']); validateHistoryPoint(value.base.point)
    check(isArray(value.base.bridge) && value.base.bridge.length <= 4096, 'PEER_PREFIX_PROOF_TOO_LARGE')
  }
}
function validateGeneration(value: GenerationRecord): void {
  object(value, ['applicationId', 'profile', 'policy', 'number', 'previous', 'coordinator', 'controlRevision', 'controlDigest', 'adopted', 'recoveryFloor', 'executionManifestDigest', 'transition'])
  hex(value.applicationId); uint(value.number); hex(value.coordinator); uint(value.controlRevision); hex(value.controlDigest); hex(value.executionManifestDigest)
  if (value.previous !== null) hex(value.previous)
  if (value.adopted !== null) validateHistoryPoint(value.adopted)
  if (value.recoveryFloor !== null) validateHistoryPoint(value.recoveryFloor)
}
export async function signApplicationDescriptor(payload: ApplicationDescriptor, signer: PeerIdentity): Promise<SignedApplicationDescriptor> {
  validateDescriptor(payload); check(payload.controlPublicKey === signer.publicKey, 'PEER_CONTROL_KEY_MISMATCH')
  return signPeerValue(DOMAINS.peerDescriptor, payload, signer)
}
/** The supported shared-application policy; every granted power remains explicit on the wire. */
export function participantGrant(publicKey: string, options: { readonly administrator?: boolean; readonly publisher?: boolean; readonly relay?: true; readonly dataRole?: 'member' | 'admin' | null } = {}): PeerGrant {
  hex(publicKey)
  return { publicKey, reader: true, writer: true, coordinator: true, recovery: true,
    administrator: options.administrator ?? false, publisher: options.publisher ?? false,
    ...(options.relay === true ? { relay: true } : {}),
    dataRole: options.dataRole === undefined ? 'member' : options.dataRole }
}
/** Explicit control-only host role, enabling account ownership recovery without a creator device. */
export function controlParticipantGrant(publicKey: string): PeerGrant {
  hex(publicKey)
  return { publicKey, reader: false, writer: false, coordinator: false, recovery: true, administrator: true, publisher: false, dataRole: null }
}
export async function signControlRevision(payload: ControlRevision, signer: PeerIdentity): Promise<SignedControlRevision> {
  validateControl(payload); return signPeerValue(DOMAINS.peerControl, payload, signer)
}
export async function signTransitionRequest(payload: TransitionRequest, signer: PeerIdentity): Promise<SignedTransitionRequest> {
  validateRequest(payload); check(payload.requester === signer.publicKey, 'PEER_REQUESTER_KEY_MISMATCH')
  return signPeerValue(DOMAINS.peerTransition, payload, signer)
}
export async function generationStartRoot(generation: SignedGeneration): Promise<string> {
  return peerDigest(['chronolog/peer-generation/start/v1', generation.id, generation.payload.adopted])
}
export async function verifyOrderReceipt(receipt: OrderReceipt, generation: SignedGeneration, descriptor: ApplicationDescriptor): Promise<void> {
  object(receipt, ['payload', 'signature', 'root']); hex(receipt.root)
  const value = receipt.payload
  object(value, ['applicationId', 'profile', 'generation', 'sequence', 'previousRoot', 'attemptId', 'author', 'operationId', 'bodyHash', 'bodyBytes'])
  scope(value, descriptor); hex(value.generation); uint(value.sequence); check(value.sequence > 0, 'PEER_ORDER_POSITION_INVALID')
  hex(value.previousRoot); hex(value.attemptId); hex(value.author); boundedText(value.operationId); hex(value.bodyHash); uint(value.bodyBytes, 2 * 1024 * 1024)
  check(value.bodyBytes > 0 && value.generation === generation.id, 'PEER_ORDER_GENERATION_MISMATCH')
  check(receipt.root === await peerDigest(['chronolog/peer-generation/order/v1', value]), 'PEER_ORDER_ROOT_MISMATCH')
  await verifyPeerValue(DOMAINS.peerOrder, { payload: value, signature: receipt.signature }, generation.payload.coordinator)
}

interface SelectedSegment { readonly generation: SignedGeneration; readonly cutoff: HistoryPoint | null }

/** Constructed only after checking the signed descriptor, control chain and every selection. */
export class PeerAuthority {
  readonly #bundle: Omit<AuthorityBundle, 'controls' | 'generations'> & { controls: SignedControlRevision[]; generations: SignedGeneration[] }
  readonly #byId = new Map<string, SignedGeneration>()
  readonly #transitions = new Map<string, SignedGeneration>()
  readonly #depth = new Map<string, number>()
  readonly #ancestors = new Map<string, readonly string[]>()
  // Construction uses cloned wire data or an already verified private prefix.
  private constructor(bundle: AuthorityBundle) { this.#bundle = { ...bundle, controls: [...bundle.controls], generations: [...bundle.generations] } }
  get signedDescriptor(): SignedApplicationDescriptor { return structuredClone(this.#bundle.descriptor) }
  get generationCount(): number { return this.#bundle.generations.length }
  get controlCount(): number { return this.#bundle.controls.length }
  generationAt(index: number): SignedGeneration | null { return structuredClone(this.#bundle.generations[index] ?? null) }
  suffix(controls: number, generations: number): Pick<AuthorityBundle, 'controls' | 'generations'> {
    uint(controls, this.controlCount); uint(generations, this.generationCount)
    return { controls: structuredClone(this.#bundle.controls.slice(controls)), generations: structuredClone(this.#bundle.generations.slice(generations)) }
  }
  transition(id: string): SignedGeneration | null { return structuredClone(this.#transitions.get(id) ?? null) }
  get bundle(): AuthorityBundle { return structuredClone(this.#bundle) }
  get descriptor(): ApplicationDescriptor { return structuredClone(this.#bundle.descriptor.payload) }
  get current(): SignedGeneration | null { return structuredClone(this.#bundle.generations.at(-1) ?? null) }
  get control(): SignedControlRevision { return structuredClone(this.#bundle.controls.at(-1)!) }
  generation(id: string): SignedGeneration {
    const value = this.#byId.get(id)
    check(value !== undefined, 'PEER_GENERATION_UNKNOWN'); return structuredClone(value)
  }
  controlAt(revision: number): SignedControlRevision {
    const value = this.#bundle.controls[revision]; check(value !== undefined, 'PEER_CONTROL_UNKNOWN'); return structuredClone(value)
  }
  grant(publicKey: string, revision = this.control.payload.revision): PeerGrant | null {
    return structuredClone(this.controlAt(revision).payload.grants.find(grant => grant.publicKey === publicKey) ?? null)
  }
  #append(generation: SignedGeneration): void {
    const parent = generation.payload.adopted?.generation
    const ancestors: string[] = parent === undefined ? [] : [parent]
    for (let level = 1; ancestors[level - 1] !== undefined; level++) {
      const ancestor = this.#ancestors.get(ancestors[level - 1]!)?.[level - 1]
      if (ancestor === undefined) break
      ancestors.push(ancestor)
    }
    this.#transitions.set(generation.payload.transition.payload.transitionId, generation)
    this.#byId.set(generation.id, generation)
    this.#depth.set(generation.id, parent === undefined ? 0 : this.#depth.get(parent)! + 1)
    this.#ancestors.set(generation.id, ancestors)
    this.#bundle.generations.push(generation)
  }
  #lift(id: string, distance: number): string | undefined {
    let current: string | undefined = id
    for (let level = 0; distance > 0 && current !== undefined; level++, distance = Math.floor(distance / 2)) {
      if (distance % 2 === 1) current = this.#ancestors.get(current)?.[level]
    }
    return current
  }
  #segment(id: string): SelectedSegment | undefined {
    const current = this.#bundle.generations.at(-1), generation = this.#byId.get(id)
    if (current === undefined || generation === undefined) return undefined
    if (id === current.id) return { generation, cutoff: null }
    const distance = this.#depth.get(current.id)! - this.#depth.get(id)!
    if (distance < 1) return undefined
    const child = this.#lift(current.id, distance - 1)
    const cutoff = child === undefined ? undefined : this.#byId.get(child)!.payload.adopted
    return cutoff?.generation === id ? { generation, cutoff } : undefined
  }
  selectedSegments(): readonly SelectedSegment[] {
    const current = this.#bundle.generations.at(-1)
    if (current === undefined) return []
    const reversed: SelectedSegment[] = [{ generation: current, cutoff: null }]
    let adopted = current.payload.adopted
    while (adopted !== null) {
      const generation = this.#byId.get(adopted.generation)!
      reversed.push({ generation, cutoff: adopted }); adopted = generation.payload.adopted
    }
    return structuredClone(reversed.reverse())
  }
  /** Structural inclusion; a complete replica additionally checks the local retained root. */
  contains(point: HistoryPoint): boolean {
    validateHistoryPoint(point)
    const segment = this.#segment(point.generation)
    return segment !== undefined && (segment.cutoff === null || point.sequence <= segment.cutoff.sequence &&
      (point.sequence !== segment.cutoff.sequence || point.root === segment.cutoff.root))
  }
  async verifyPrefix(proof: PrefixProof): Promise<void> {
    object(proof, ['point', 'receipt', 'bridge']); validateHistoryPoint(proof.point)
    check(isArray(proof.bridge) && proof.bridge.length <= 4096, 'PEER_PREFIX_PROOF_TOO_LARGE')
    const segment = this.#segment(proof.point.generation)
    check(segment !== undefined && this.contains(proof.point), 'PEER_PREFIX_EXCLUDED')
    const { point } = proof
    if (point.sequence === 0) {
      check(proof.receipt === null && point.root === await generationStartRoot(segment.generation), 'PEER_PREFIX_ROOT_MISMATCH')
    } else {
      check(proof.receipt !== null, 'PEER_PREFIX_RECEIPT_REQUIRED')
      await verifyOrderReceipt(proof.receipt, segment.generation, this.descriptor)
      check(proof.receipt.payload.sequence === point.sequence && proof.receipt.root === point.root, 'PEER_PREFIX_ROOT_MISMATCH')
    }
    let position = point.sequence, root = point.root
    for (const receipt of proof.bridge) {
      await verifyOrderReceipt(receipt, segment.generation, this.descriptor)
      check(receipt.payload.sequence === position + 1 && receipt.payload.previousRoot === root, 'PEER_PREFIX_BRIDGE_INVALID')
      position++; root = receipt.root
    }
    if (segment.cutoff === null) check(proof.bridge.length === 0, 'PEER_PREFIX_BRIDGE_UNNECESSARY')
    else check(position === segment.cutoff.sequence && root === segment.cutoff.root, 'PEER_PREFIX_BRIDGE_INCOMPLETE')
  }
  /** Compare points on the selected history after their roots have been authenticated. */
  atOrAfter(point: HistoryPoint, floor: HistoryPoint): boolean {
    const left = this.#segment(point.generation), right = this.#segment(floor.generation)
    return left !== undefined && right !== undefined && (left.generation.payload.number > right.generation.payload.number ||
      point.generation === floor.generation && point.sequence >= floor.sequence)
  }
  async authorizeTransition(request: SignedTransitionRequest, nextControl = this.control): Promise<void> {
    validateRequest(request.payload); scope(request.payload, this.descriptor)
    await verifyPeerValue(DOMAINS.peerTransition, request, request.payload.requester)
    const value = request.payload, current = this.current, currentControl = this.control
    check(value.expectedGeneration === (current?.id ?? null), 'PEER_GENERATION_CONFLICT')
    check(value.controlRevision === nextControl.payload.revision, 'PEER_CONTROL_REVISION_MISMATCH')
    const requester = this.grant(value.requester, currentControl.payload.revision)
    const candidate = nextControl.payload.grants.find(grant => grant.publicKey === value.coordinator)
    check(requester?.recovery === true, 'PEER_RECOVERY_FORBIDDEN')
    check(candidate?.coordinator === true && candidate.reader, 'PEER_COORDINATOR_FORBIDDEN')
    if (current === null) {
      check(value.reason === 'create' && value.base === null && nextControl.payload.revision === 0, 'PEER_INITIAL_SELECTION_INVALID')
    } else {
      check(value.reason !== 'create' && value.base !== null, 'PEER_RECOVERY_BASE_REQUIRED')
      await this.verifyPrefix(value.base)
      if (value.reason === 'handover') check(value.requester === current.payload.coordinator, 'PEER_HANDOVER_FORBIDDEN')
      if (nextControl.payload.revision !== currentControl.payload.revision) {
        check(value.reason === 'control-change' && requester.administrator, 'PEER_CONTROL_CHANGE_FORBIDDEN')
        await verifyNextControl(this.descriptor, currentControl, nextControl)
      } else check(value.reason !== 'control-change', 'PEER_CONTROL_CHANGE_REQUIRED')
      const previousFloor = currentControl.payload.recoveryFloor
      const floor = nextControl.payload.recoveryFloor
      if (previousFloor !== null) {
        check(floor !== null && this.contains(floor) && this.atOrAfter(floor, previousFloor), 'PEER_RECOVERY_FLOOR_REGRESSION')
      }
      if (floor !== null) check(this.contains(floor) && this.atOrAfter(value.base.point, floor), 'PEER_RECOVERY_FLOOR_UNAVAILABLE')
      // A newly protected boundary is exactly the adopted complete base. It cannot
      // claim protection for a root whose relation to that base was never checked.
      if (floor !== null && !samePeerValue(floor, previousFloor)) check(samePeerValue(floor, value.base.point), 'PEER_NEW_FLOOR_MUST_MATCH_BASE')
    }
  }
  /** Verify only new signed suffix records, preserving the verified prefix by reference. */
  async extend(inputControls: readonly SignedControlRevision[], inputGenerations: readonly SignedGeneration[]): Promise<PeerAuthority> {
    if (inputControls.length === 0 && inputGenerations.length === 0) return this
    const controls = structuredClone(inputControls), generations = structuredClone(inputGenerations)
    check(this.controlCount + controls.length <= 4096 && this.generationCount + generations.length <= 4096, 'PEER_AUTHORITY_LIMIT')
    const next = new PeerAuthority(this.#bundle)
    for (const [id, value] of this.#byId) next.#byId.set(id, value)
    for (const [id, value] of this.#depth) next.#depth.set(id, value)
    for (const [id, value] of this.#ancestors) next.#ancestors.set(id, value)
    for (const [id, value] of this.#transitions) next.#transitions.set(id, value)
    const allControls = [...this.#bundle.controls, ...controls], descriptor = this.descriptor
    for (let index = this.controlCount; index < allControls.length; index++) await verifyNextControl(descriptor, allControls[index - 1]!, allControls[index]!)
    for (const generation of generations) {
      object(generation, ['payload', 'signature', 'id']); hex(generation.id); validateGeneration(generation.payload)
      const value = generation.payload; scope(value, descriptor)
      await verifyPeerValue(DOMAINS.peerGeneration, { payload: value, signature: generation.signature }, descriptor.controlPublicKey)
      check(generation.id === await peerDigest(['chronolog/peer-generation/generation/v1', value]), 'PEER_GENERATION_ID_INVALID')
      check(value.number === next.generationCount && value.previous === (next.current?.id ?? null), 'PEER_GENERATION_CHAIN_INVALID')
      const control = allControls[value.controlRevision]
      check(control !== undefined && value.controlDigest === await peerDigest(control), 'PEER_CONTROL_DIGEST_MISMATCH')
      check(value.controlRevision === next.controlCount - 1 || value.controlRevision === next.controlCount, 'PEER_CONTROL_CHAIN_INVALID')
      await next.authorizeTransition(value.transition, control)
      check(value.coordinator === value.transition.payload.coordinator && samePeerValue(value.adopted, value.transition.payload.base?.point ?? null) &&
        samePeerValue(value.recoveryFloor, control.payload.recoveryFloor) && value.executionManifestDigest === descriptor.executionManifestDigest, 'PEER_DELEGATION_MISMATCH')
      check(!next.#transitions.has(value.transition.payload.transitionId), 'PEER_TRANSITION_DUPLICATE')
      if (value.controlRevision === next.controlCount) next.#bundle.controls.push(control)
      next.#append(generation)
    }
    check(next.controlCount === allControls.length, 'PEER_CONTROL_NOT_ACTIVATED')
    return next
  }
  static async verify(input: AuthorityBundle, pinned?: SignedApplicationDescriptor): Promise<PeerAuthority> {
    const bundle = structuredClone(input)
    object(bundle, ['descriptor', 'controls', 'generations'])
    validateDescriptor(bundle.descriptor.payload)
    await verifyPeerValue(DOMAINS.peerDescriptor, bundle.descriptor, bundle.descriptor.payload.controlPublicKey)
    if (pinned !== undefined) check(samePeerValue(bundle.descriptor, pinned), 'PEER_DESCRIPTOR_CHANGED')
    check(isArray(bundle.controls) && bundle.controls.length > 0 && bundle.controls.length <= 4096 &&
      isArray(bundle.generations) && bundle.generations.length <= 4096, 'PEER_AUTHORITY_LIMIT')
    const descriptor = bundle.descriptor.payload
    for (const [index, control] of bundle.controls.entries()) {
      validateControl(control.payload); scope(control.payload, descriptor)
      await verifyPeerValue(DOMAINS.peerControl, control, descriptor.controlPublicKey)
      check(control.payload.revision === index, 'PEER_CONTROL_CHAIN_INVALID')
      if (index === 0) check(control.payload.previous === null && control.payload.recoveryFloor === null, 'PEER_INITIAL_CONTROL_INVALID')
      else await verifyNextControl(descriptor, bundle.controls[index - 1]!, control)
    }
    const verified = new PeerAuthority({ descriptor: bundle.descriptor, controls: [bundle.controls[0]!], generations: [] })
    const transitions = new Set<string>()
    for (const [number, generation] of bundle.generations.entries()) {
      object(generation, ['payload', 'signature', 'id']); hex(generation.id); validateGeneration(generation.payload)
      const value = generation.payload; scope(value, descriptor)
      await verifyPeerValue(DOMAINS.peerGeneration, { payload: value, signature: generation.signature }, descriptor.controlPublicKey)
      check(generation.id === await peerDigest(['chronolog/peer-generation/generation/v1', value]), 'PEER_GENERATION_ID_INVALID')
      check(value.number === number && value.previous === (verified.current?.id ?? null), 'PEER_GENERATION_CHAIN_INVALID')
      const control = bundle.controls[value.controlRevision]
      check(control !== undefined && value.controlDigest === await peerDigest(control), 'PEER_CONTROL_DIGEST_MISMATCH')
      check(value.controlRevision === verified.control.payload.revision || value.controlRevision === verified.control.payload.revision + 1, 'PEER_CONTROL_CHAIN_INVALID')
      await verified.authorizeTransition(value.transition, control)
      check(value.coordinator === value.transition.payload.coordinator &&
        samePeerValue(value.adopted, value.transition.payload.base?.point ?? null) &&
        samePeerValue(value.recoveryFloor, control.payload.recoveryFloor) &&
        value.executionManifestDigest === descriptor.executionManifestDigest, 'PEER_DELEGATION_MISMATCH')
      check(!transitions.has(value.transition.payload.transitionId), 'PEER_TRANSITION_DUPLICATE'); transitions.add(value.transition.payload.transitionId)
      if (value.controlRevision >= verified.#bundle.controls.length) verified.#bundle.controls.push(control)
      verified.#append(generation)
    }
    check(verified.control.payload.revision === bundle.controls.length - 1, 'PEER_CONTROL_NOT_ACTIVATED')
    return verified
  }
}

async function verifyNextControl(descriptor: ApplicationDescriptor, previous: SignedControlRevision, next: SignedControlRevision): Promise<void> {
  validateControl(next.payload); scope(next.payload, descriptor)
  await verifyPeerValue(DOMAINS.peerControl, next, descriptor.controlPublicKey)
  check(next.payload.revision === previous.payload.revision + 1 && next.payload.previous === await peerDigest(previous) && next.payload.epoch >= previous.payload.epoch,
    'PEER_CONTROL_CHAIN_INVALID')
  const revokedReader = previous.payload.grants.some(old => old.reader && !next.payload.grants.some(grant => grant.publicKey === old.publicKey && grant.reader))
  if (revokedReader) check(next.payload.epoch > previous.payload.epoch && next.payload.keyDigest !== previous.payload.keyDigest, 'PEER_REVOCATION_REQUIRES_KEY_ROTATION')
  if (next.payload.epoch === previous.payload.epoch) check(next.payload.keyDigest === previous.payload.keyDigest, 'PEER_EPOCH_KEY_CHANGED')
}
export function verifyAuthorityBundle(bundle: AuthorityBundle, pinned?: SignedApplicationDescriptor): Promise<PeerAuthority> {
  return PeerAuthority.verify(bundle, pinned)
}

export interface GenerationRegistry {
  read(): Promise<AuthorityBundle>
  select(request: SignedTransitionRequest, options?: { readonly control?: SignedControlRevision }): Promise<SignedGeneration>
}
const registryLocks = new WeakMap<BytesStore, Map<string, Serial>>()
function registryLock(store: BytesStore, key: string): Serial {
  let keys = registryLocks.get(store)
  if (keys === undefined) { keys = new Map(); registryLocks.set(store, keys) }
  let lock = keys.get(key)
  if (lock === undefined) { lock = new Serial(); keys.set(key, lock) }
  return lock
}
interface RegistryHead { readonly format: 'chronolog-authority-log-v1'; readonly length: number }
interface RegistryEntry { readonly generation: SignedGeneration; readonly control: SignedControlRevision | null }
interface RegistryCache { readonly head: string; readonly authority: PeerAuthority }
const registryCaches = new WeakMap<BytesStore, Map<string, RegistryCache>>()

/** Append signed records before atomically publishing a small head. Legacy bundles migrate on selection. */
export async function createGenerationRegistry(options: {
  readonly store: BytesStore
  readonly descriptor: SignedApplicationDescriptor
  readonly controls: readonly SignedControlRevision[]
  readonly signer: PeerIdentity
  readonly requireExisting?: boolean
}): Promise<GenerationRegistry> {
  const key = `peer-generation/registry/${options.descriptor.payload.applicationId}`, lock = registryLock(options.store, key)
  let caches = registryCaches.get(options.store)
  if (caches === undefined) { caches = new Map(); registryCaches.set(options.store, caches) }
  const cache = caches
  check(options.signer.publicKey === options.descriptor.payload.controlPublicKey, 'PEER_CONTROL_KEY_MISMATCH')
  const read = async (): Promise<PeerAuthority> => {
    const bytes = await options.store.get(key); check(bytes !== null, 'PEER_CONTROL_STATE_MISSING')
    const head = bytesToHex(bytes), retained = cache.get(key)
    if (retained?.head === head) { check(samePeerValue(retained.authority.signedDescriptor, options.descriptor), 'PEER_DESCRIPTOR_CHANGED'); return retained.authority }
    const decoded = decodePeerValue<AuthorityBundle | RegistryHead>(bytes)
    let bundle: AuthorityBundle
    if ('format' in decoded) {
      object(decoded, ['format', 'length'])
      check(decoded.format === 'chronolog-authority-log-v1', 'PEER_CONTROL_STATE_INVALID'); uint(decoded.length, 4096)
      const base = await options.store.get(`${key}/base`); check(base !== null, 'PEER_CONTROL_STATE_MISSING')
      bundle = decodePeerValue<AuthorityBundle>(base)
      check(bundle.generations.length <= decoded.length, 'PEER_CONTROL_STATE_INVALID')
      const controls = [...bundle.controls], generations = [...bundle.generations]
      for (let index = generations.length; index < decoded.length; index++) {
        const raw = await options.store.get(`${key}/log/${index}`); check(raw !== null, 'PEER_CONTROL_STATE_MISSING')
        const entry = decodePeerValue<RegistryEntry>(raw); object(entry, ['generation', 'control'])
        generations.push(entry.generation)
        if (entry.control !== null) controls.push(entry.control)
      }
      bundle = { descriptor: bundle.descriptor, controls, generations }
    } else bundle = decoded
    const authority = await verifyAuthorityBundle(bundle, options.descriptor)
    cache.set(key, { head, authority })
    return authority
  }
  await lock.run(async () => {
    if (await options.store.get(key) === null) {
      check(options.requireExisting !== true, 'PEER_CONTROL_STATE_MISSING')
      const initial = { descriptor: options.descriptor, controls: options.controls, generations: [] }
      await verifyAuthorityBundle(initial)
      await options.store.put(`${key}/base`, encodePeerValue(initial))
      await options.store.put(key, encodePeerValue({ format: 'chronolog-authority-log-v1', length: 0 } satisfies RegistryHead))
    }
    await read()
  })
  return {
    read: () => lock.run(async () => (await read()).bundle),
    async select(input, inputOptions = {}) {
      const request = structuredClone(input), next = structuredClone(inputOptions.control)
      return lock.run(async () => {
        const authority = await read()
        validateRequest(request.payload)
        await verifyPeerValue(DOMAINS.peerTransition, request, request.payload.requester)
        const retry = authority.transition(request.payload.transitionId)
        if (retry !== null) {
          check(samePeerValue(retry.payload.transition, request), 'PEER_TRANSITION_ID_REUSED')
          if (next !== undefined) check(samePeerValue(authority.controlAt(retry.payload.controlRevision), next), 'PEER_TRANSITION_ID_REUSED')
          return retry
        }
        const control = next ?? authority.control
        await authority.authorizeTransition(request, control)
        const payload: GenerationRecord = {
          applicationId: authority.descriptor.applicationId, profile: PEER_GENERATION_PROFILE, policy: PEER_GENERATION_POLICY,
          number: authority.generationCount, previous: authority.current?.id ?? null,
          coordinator: request.payload.coordinator, controlRevision: control.payload.revision,
          controlDigest: await peerDigest(control), adopted: request.payload.base?.point ?? null,
          recoveryFloor: control.payload.recoveryFloor, executionManifestDigest: authority.descriptor.executionManifestDigest, transition: request,
        }
        const signed = await signPeerValue(DOMAINS.peerGeneration, payload, options.signer)
        const generation = { ...signed, id: await peerDigest(['chronolog/peer-generation/generation/v1', payload]) }
        const updated = await authority.extend(next === undefined ? [] : [next], [generation])
        const currentBytes = await options.store.get(key); check(currentBytes !== null, 'PEER_CONTROL_STATE_MISSING')
        if (!('format' in decodePeerValue<AuthorityBundle | RegistryHead>(currentBytes))) {
          await options.store.put(`${key}/base`, encodePeerValue(authority.bundle))
        }
        await options.store.put(`${key}/log/${generation.payload.number}`, encodePeerValue({ generation, control: next ?? null } satisfies RegistryEntry))
        const head = encodePeerValue({ format: 'chronolog-authority-log-v1', length: updated.generationCount } satisfies RegistryHead)
        await options.store.put(key, head)
        cache.set(key, { head: bytesToHex(head), authority: updated })
        return structuredClone(generation)
      })
    },
  }
}
