import { DOMAINS } from '@chronolog/protocol'
import {
  boundedText, check, isArray, decodePeerValue, encodePeerValue, hex, object, peerDigest,
  samePeerValue, Serial, signPeerValue, uint, verifyPeerValue,
} from './codec.js'
import {
  PEER_GENERATION_POLICY, PEER_GENERATION_PROFILE,
  type ApplicationDescriptor, type AuthorityBundle, type ControlRevision, type GenerationRecord,
  type HistoryPoint, type OrderReceipt, type PeerGrant, type PeerIdentity, type PeerStore,
  type PrefixProof, type SignedApplicationDescriptor, type SignedControlRevision,
  type SignedGeneration, type SignedTransitionRequest, type TransitionRequest,
} from './control-types.js'

export * from './control-types.js'
export { createPeerIdentity, exportPeerIdentity, importPeerIdentity, PeerGenerationError, encodePeerValue, decodePeerValue, peerDigest, bytesDigest } from './codec.js'

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
    object(grant, ['publicKey', 'reader', 'writer', 'coordinator', 'recovery', 'administrator', 'dataRole']); hex(grant.publicKey)
    for (const key of ['reader', 'writer', 'coordinator', 'recovery', 'administrator'] as const) check(typeof grant[key] === 'boolean', 'PEER_GRANT_INVALID')
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
export function participantGrant(publicKey: string, options: { readonly administrator?: boolean; readonly dataRole?: 'member' | 'admin' | null } = {}): PeerGrant {
  hex(publicKey)
  return { publicKey, reader: true, writer: true, coordinator: true, recovery: true,
    administrator: options.administrator ?? false, dataRole: options.dataRole === undefined ? 'member' : options.dataRole }
}
/** Explicit control-only host role, enabling account ownership recovery without a creator device. */
export function controlParticipantGrant(publicKey: string): PeerGrant {
  hex(publicKey)
  return { publicKey, reader: false, writer: false, coordinator: false, recovery: true, administrator: true, dataRole: null }
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
  readonly #bundle: AuthorityBundle
  private constructor(bundle: AuthorityBundle) { this.#bundle = structuredClone(bundle) }
  get bundle(): AuthorityBundle { return structuredClone(this.#bundle) }
  get descriptor(): ApplicationDescriptor { return structuredClone(this.#bundle.descriptor.payload) }
  get current(): SignedGeneration | null { return structuredClone(this.#bundle.generations.at(-1) ?? null) }
  get control(): SignedControlRevision { return structuredClone(this.#bundle.controls.at(-1)!) }
  generation(id: string): SignedGeneration {
    const value = this.#bundle.generations.find(generation => generation.id === id)
    check(value !== undefined, 'PEER_GENERATION_UNKNOWN'); return structuredClone(value)
  }
  controlAt(revision: number): SignedControlRevision {
    const value = this.#bundle.controls[revision]; check(value !== undefined, 'PEER_CONTROL_UNKNOWN'); return structuredClone(value)
  }
  grant(publicKey: string, revision = this.control.payload.revision): PeerGrant | null {
    return structuredClone(this.controlAt(revision).payload.grants.find(grant => grant.publicKey === publicKey) ?? null)
  }
  selectedSegments(): readonly SelectedSegment[] {
    const current = this.current
    if (current === null) return []
    const reversed: SelectedSegment[] = [{ generation: current, cutoff: null }]
    let adopted = current.payload.adopted
    while (adopted !== null) {
      const generation = this.generation(adopted.generation)
      reversed.push({ generation, cutoff: adopted }); adopted = generation.payload.adopted
      check(reversed.length <= this.#bundle.generations.length, 'PEER_ANCESTRY_CYCLE')
    }
    return reversed.reverse()
  }
  /** Structural inclusion; a complete replica additionally checks the local retained root. */
  contains(point: HistoryPoint): boolean {
    validateHistoryPoint(point)
    const segment = this.selectedSegments().find(value => value.generation.id === point.generation)
    return segment !== undefined && (segment.cutoff === null || point.sequence <= segment.cutoff.sequence &&
      (point.sequence !== segment.cutoff.sequence || point.root === segment.cutoff.root))
  }
  async verifyPrefix(proof: PrefixProof): Promise<void> {
    object(proof, ['point', 'receipt', 'bridge']); validateHistoryPoint(proof.point)
    check(isArray(proof.bridge) && proof.bridge.length <= 4096, 'PEER_PREFIX_PROOF_TOO_LARGE')
    const segment = this.selectedSegments().find(value => value.generation.id === proof.point.generation)
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
    const segments = this.selectedSegments()
    const left = segments.findIndex(value => value.generation.id === point.generation)
    const right = segments.findIndex(value => value.generation.id === floor.generation)
    return left >= 0 && right >= 0 && (left > right || left === right && point.sequence >= floor.sequence)
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
    let verified = new PeerAuthority({ descriptor: bundle.descriptor, controls: [bundle.controls[0]!], generations: [] })
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
      verified = new PeerAuthority({ descriptor: bundle.descriptor, controls: bundle.controls.slice(0, value.controlRevision + 1), generations: bundle.generations.slice(0, number + 1) })
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
const registryLocks = new WeakMap<PeerStore, Map<string, Serial>>()
function registryLock(store: PeerStore, key: string): Serial {
  let keys = registryLocks.get(store)
  if (keys === undefined) { keys = new Map(); registryLocks.set(store, keys) }
  let lock = keys.get(key)
  if (lock === undefined) { lock = new Serial(); keys.set(key, lock) }
  return lock
}
/** The host owns an exclusive durable store; no command body is accepted by this service. */
export async function createGenerationRegistry(options: {
  readonly store: PeerStore
  readonly descriptor: SignedApplicationDescriptor
  readonly controls: readonly SignedControlRevision[]
  readonly signer: PeerIdentity
  readonly requireExisting?: boolean
}): Promise<GenerationRegistry> {
  const key = `peer-generation/registry/${options.descriptor.payload.applicationId}`
  const lock = registryLock(options.store, key)
  check(options.signer.publicKey === options.descriptor.payload.controlPublicKey, 'PEER_CONTROL_KEY_MISMATCH')
  const read = async (): Promise<AuthorityBundle> => {
    const bytes = await options.store.get(key); check(bytes !== null, 'PEER_CONTROL_STATE_MISSING')
    const bundle = decodePeerValue<AuthorityBundle>(bytes)
    await verifyAuthorityBundle(bundle, options.descriptor); return bundle
  }
  await lock.run(async () => {
    if (await options.store.get(key) === null) {
      check(options.requireExisting !== true, 'PEER_CONTROL_STATE_MISSING')
      const initial = { descriptor: options.descriptor, controls: options.controls, generations: [] }
      await verifyAuthorityBundle(initial)
      await options.store.put(key, encodePeerValue(initial))
    }
    await read()
  })
  return {
    read: () => lock.run(read),
    async select(input, inputOptions = {}) {
      const request = structuredClone(input), next = structuredClone(inputOptions.control)
      return lock.run(async () => {
        const bundle = await read(), authority = await verifyAuthorityBundle(bundle)
        validateRequest(request.payload)
        await verifyPeerValue(DOMAINS.peerTransition, request, request.payload.requester)
        const retry = bundle.generations.find(value => value.payload.transition.payload.transitionId === request.payload.transitionId)
        if (retry !== undefined) {
          check(samePeerValue(retry.payload.transition, request), 'PEER_TRANSITION_ID_REUSED')
          if (next !== undefined) check(samePeerValue(bundle.controls[retry.payload.controlRevision], next), 'PEER_TRANSITION_ID_REUSED')
          return retry
        }
        const control = next ?? authority.control
        await authority.authorizeTransition(request, control)
        const payload: GenerationRecord = {
          applicationId: authority.descriptor.applicationId, profile: PEER_GENERATION_PROFILE, policy: PEER_GENERATION_POLICY,
          number: bundle.generations.length, previous: authority.current?.id ?? null,
          coordinator: request.payload.coordinator, controlRevision: control.payload.revision,
          controlDigest: await peerDigest(control), adopted: request.payload.base?.point ?? null,
          recoveryFloor: control.payload.recoveryFloor, executionManifestDigest: authority.descriptor.executionManifestDigest,
          transition: request,
        }
        const signed = await signPeerValue(DOMAINS.peerGeneration, payload, options.signer)
        const generation = { ...signed, id: await peerDigest(['chronolog/peer-generation/generation/v1', payload]) }
        const updated = { descriptor: bundle.descriptor,
          controls: next === undefined ? bundle.controls : [...bundle.controls, next], generations: [...bundle.generations, generation] }
        await verifyAuthorityBundle(updated, options.descriptor)
        // This atomic pointer publishes controls and generation together. A lost
        // acknowledgment is resolved by rereading this exact transition identity.
        await options.store.put(key, encodePeerValue(updated))
        return structuredClone(generation)
      })
    },
  }
}
