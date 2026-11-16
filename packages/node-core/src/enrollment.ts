import {
  capabilityId, capabilityRevisionDigest, encodeGenesisManifest, encodeSignedCapabilityRevision,
  decodeSignedCapabilityRevision, isCapabilityActive, verifySignedGenesis,
  normalizeProgramRights, programRightsSubset, type ProgramRights,
  type CapabilityGrant, type CapabilitySnapshot, type SignedCapabilityRevision, type SignedGenesis,
} from '@chronolog/capabilities'
import {
  exportX25519PrivateKey, generateX25519KeyPair, importX25519PrivateKey, importX25519PublicKey,
  type X25519KeyPair,
} from '@chronolog/crypto'
import {
  DOMAINS, assertCanonicalCbor, bytesToHex, encodeCanonicalCbor, equalBytes,
  exportEd25519PrivateKey, generateEd25519KeyPair, hashDomain,
  importEd25519PrivateKey, importEd25519PublicKey, signDomain, verifyDomain,
  type CborValue, type Ed25519KeyPair,
} from '@chronolog/protocol'

import { Mutex } from './async.js'
import type { GovernanceControlPlane } from './governance.js'
import { historyConfigurationDigest, type HistoryConfiguration } from './history-policy.js'
import { validateOperationId, type DurableOperationStore } from './operations.js'

export type EnrollmentRole = 'reader' | 'writer'

export interface EnrollmentDescriptor {
  readonly genesis: SignedGenesis
  readonly groupRoute: Uint8Array
  readonly history: HistoryConfiguration
}

export interface EnrollmentIdentity {
  readonly signing: Ed25519KeyPair
  readonly reader: X25519KeyPair
}

export interface EnrollmentRequest {
  readonly writerProgram?: ProgramRights
  readonly requestId: string
  readonly groupId: Uint8Array
  readonly genesisDigest: Uint8Array
  readonly policyDigest: Uint8Array
  readonly executionManifestDigest: Uint8Array
  readonly signingPublicKey: Uint8Array
  readonly readerPublicKey: Uint8Array
  readonly transportAuthor: string
  readonly requestedRoles: readonly EnrollmentRole[]
  readonly historyAccess: 'full'
}

export interface SignedEnrollmentRequest {
  readonly request: EnrollmentRequest
  readonly signature: Uint8Array
}

/** A captured immutable prefix, interpreted by the selected history policy. */
export interface EnrollmentFinalTarget {
  readonly frontier: Uint8Array
  readonly requiredEpochs: readonly bigint[]
  readonly executionManifestDigest: Uint8Array
}

export interface EnrollmentApproval {
  readonly writerProgram?: ProgramRights
  readonly requestId: string
  readonly requestDigest: Uint8Array
  readonly groupId: Uint8Array
  readonly membershipRevision: Uint8Array
  readonly grantedRevision: bigint
  readonly roles: readonly EnrollmentRole[]
  readonly capabilityIds: readonly Uint8Array[]
  readonly fullHistoryGranted: boolean
  readonly target: EnrollmentFinalTarget
}

export interface SignedEnrollmentApproval {
  readonly approval: EnrollmentApproval
  readonly signature: Uint8Array
}

const storeLocks = new WeakMap<DurableOperationStore, Mutex>()
function storeLock(store: DurableOperationStore): Mutex {
  let mutex = storeLocks.get(store)
  if (mutex === undefined) { mutex = new Mutex(); storeLocks.set(store, mutex) }
  return mutex
}

/** Generate once on the joining device; private material never enters a request. */
export async function loadOrCreateEnrollmentIdentity(store: DurableOperationStore, namespace: string): Promise<EnrollmentIdentity> {
  validateOperationId(namespace)
  return storeLock(store).run(async () => {
    const key = `enrollment/identity/${encodeURIComponent(namespace)}`
    let saved = await store.get(key)
    if (saved === null) {
      const signing = await generateEd25519KeyPair()
      const reader = await generateX25519KeyPair()
      saved = encodeCanonicalCbor([
        1n, signing.publicKeyBytes, await exportEd25519PrivateKey(signing.privateKey),
        reader.publicKeyBytes, await exportX25519PrivateKey(reader.privateKey),
      ])
      await store.put(key, saved)
    }
    const value = array(saved, 5)
    if (value[0] !== 1n) throw new Error('ENROLLMENT_IDENTITY_INVALID')
    const signingPublicKey = bytes(value[1], 32)
    const readerPublicKey = bytes(value[3], 32)
    const signing = {
      publicKeyBytes: signingPublicKey,
      publicKey: await importEd25519PublicKey(signingPublicKey),
      privateKey: await importEd25519PrivateKey(bytes(value[2])),
    }
    const reader = {
      publicKeyBytes: readerPublicKey,
      publicKey: await importX25519PublicKey(readerPublicKey),
      privateKey: await importX25519PrivateKey(bytes(value[4])),
    }
    return { signing, reader }
  })
}

/** Persist the signed request before returning bytes that can be delivered. */
export async function prepareEnrollmentRequest(options: {
  readonly descriptor: EnrollmentDescriptor
  readonly store: DurableOperationStore
  readonly requestId: string
  readonly identity: Ed25519KeyPair
  readonly readerPublicKey: Uint8Array
  readonly transportAuthor: string
  readonly requestedRoles: readonly EnrollmentRole[]
  readonly writerProgram?: ProgramRights
}): Promise<SignedEnrollmentRequest> {
  await verifyEnrollmentDescriptor(options.descriptor)
  const request: EnrollmentRequest = {
    requestId: options.requestId, groupId: options.descriptor.history.groupId,
    genesisDigest: options.descriptor.history.genesisDigest,
    policyDigest: await historyConfigurationDigest(options.descriptor.history),
    executionManifestDigest: options.descriptor.history.executionManifestDigest,
    signingPublicKey: options.identity.publicKeyBytes, readerPublicKey: options.readerPublicKey,
    transportAuthor: options.transportAuthor, requestedRoles: roles(options.requestedRoles), historyAccess: 'full',
    ...(options.writerProgram === undefined ? {} : { writerProgram: normalizeProgramRights(options.writerProgram) }),
  }
  const payload = encodeEnrollmentRequest(request)
  return storeLock(options.store).run(async () => {
    const key = `enrollment/request/${bytesToHex(request.groupId)}/${encodeURIComponent(request.requestId)}`
    const saved = await options.store.get(key)
    if (saved !== null) {
      const original = decodeSignedEnrollmentRequest(saved)
      if (!equalBytes(encodeEnrollmentRequest(original.request), payload)) throw new Error('ENROLLMENT_REQUEST_ID_CONFLICT')
      if (!await verifySignedEnrollmentRequest(original)) throw new Error('ENROLLMENT_STORED_REQUEST_INVALID')
      return original
    }
    const signed = { request, signature: await signDomain(DOMAINS.enrollmentRequest, payload, options.identity.privateKey) }
    await options.store.put(key, encodeSignedEnrollmentRequest(signed))
    return signed
  })
}

export async function loadEnrollmentRequest(store: DurableOperationStore, groupId: Uint8Array, requestId: string): Promise<SignedEnrollmentRequest | null> {
  validateOperationId(requestId)
  const saved = await store.get(`enrollment/request/${bytesToHex(groupId)}/${encodeURIComponent(requestId)}`)
  return saved === null ? null : decodeSignedEnrollmentRequest(saved)
}

export async function saveEnrollmentApproval(options: {
  readonly descriptor: EnrollmentDescriptor
  readonly request: SignedEnrollmentRequest
  readonly approval: SignedEnrollmentApproval
  readonly store: DurableOperationStore
}): Promise<void> {
  await verifyEnrollmentApproval(options.descriptor, options.request, options.approval)
  const key = approvalKey(options.request.request)
  const encoded = encodeSignedEnrollmentApproval(options.approval)
  await storeLock(options.store).run(async () => {
    const saved = await options.store.get(key)
    if (saved !== null && !equalBytes(saved, encoded)) throw new Error('ENROLLMENT_APPROVAL_CONFLICT')
    await options.store.put(key, encoded)
  })
}

export async function loadEnrollmentApproval(store: DurableOperationStore, request: EnrollmentRequest): Promise<SignedEnrollmentApproval | null> {
  const saved = await store.get(approvalKey(request))
  return saved === null ? null : decodeSignedEnrollmentApproval(saved)
}

function approvalKey(request: EnrollmentRequest): string {
  return `enrollment/approval/${bytesToHex(request.groupId)}/${encodeURIComponent(request.requestId)}`
}

export async function verifyEnrollmentDescriptor(descriptor: EnrollmentDescriptor): Promise<void> {
  const { genesis, history } = descriptor
  if (!await verifySignedGenesis(genesis) || descriptor.groupRoute.length !== 32 ||
      !equalBytes(genesis.manifest.groupId, history.groupId) ||
      !equalBytes(await hashDomain(DOMAINS.genesis, encodeGenesisManifest(genesis.manifest)), history.genesisDigest) ||
      !equalBytes(genesis.manifest.schemaId, history.executionManifestDigest)) throw new Error('ENROLLMENT_DESCRIPTOR_INVALID')
  const configured = genesis.manifest.historyPolicy
  if (configured === undefined) {
    if (history.kind !== 'peer') throw new Error('ENROLLMENT_POLICY_NOT_AUTHENTICATED')
  } else if (configured.kind !== history.kind || !equalBytes(configured.executionManifestDigest, history.executionManifestDigest) ||
      (history.kind === 'coordinated' && (configured.historyId !== history.historyId ||
        configured.authorityPublicKey === undefined || !equalBytes(configured.authorityPublicKey, history.authorityPublicKey)))) {
    throw new Error('ENROLLMENT_POLICY_NOT_AUTHENTICATED')
  }
}

export function encodeEnrollmentRequest(request: EnrollmentRequest): Uint8Array {
  validateOperationId(request.requestId)
  for (const value of [request.groupId, request.genesisDigest, request.policyDigest, request.executionManifestDigest,
    request.signingPublicKey, request.readerPublicKey]) if (value.length !== 32) throw new Error('ENROLLMENT_REQUEST_INVALID')
  if (request.transportAuthor.length === 0 || request.transportAuthor.length > 512 || request.historyAccess !== 'full') {
    throw new Error('ENROLLMENT_REQUEST_INVALID')
  }
  if (request.writerProgram !== undefined && !request.requestedRoles.includes('writer')) throw new Error('ENROLLMENT_PROGRAM_WITHOUT_WRITER')
  return encodeCanonicalCbor([
    2n, request.requestId, request.groupId, request.genesisDigest, request.policyDigest,
    request.executionManifestDigest, request.signingPublicKey, request.readerPublicKey,
    request.transportAuthor, roles(request.requestedRoles), request.historyAccess, rightsValue(request.writerProgram),
  ])
}

export function encodeSignedEnrollmentRequest(signed: SignedEnrollmentRequest): Uint8Array {
  if (signed.signature.length !== 64) throw new Error('ENROLLMENT_REQUEST_INVALID')
  return encodeCanonicalCbor([encodeEnrollmentRequest(signed.request), signed.signature])
}

export function decodeSignedEnrollmentRequest(encoded: Uint8Array): SignedEnrollmentRequest {
  const signed = array(encoded, 2)
  const value = array(bytes(signed[0]), 12)
  if (value[0] !== 2n || value[10] !== 'full') throw new Error('ENROLLMENT_REQUEST_INVALID')
  const request: EnrollmentRequest = {
    requestId: string(value[1]), groupId: bytes(value[2], 32), genesisDigest: bytes(value[3], 32),
    policyDigest: bytes(value[4], 32), executionManifestDigest: bytes(value[5], 32),
    signingPublicKey: bytes(value[6], 32), readerPublicKey: bytes(value[7], 32),
    transportAuthor: string(value[8]), requestedRoles: rolesValue(value[9]), historyAccess: 'full',
    ...(value[11] === null ? {} : { writerProgram: rightsFromValue(value[11]) }),
  }
  // Noncanonical role ordering/duplicates cannot acquire a different identity.
  if (!equalBytes(encodeEnrollmentRequest(request), bytes(signed[0]))) throw new Error('ENROLLMENT_REQUEST_INVALID')
  return { request, signature: bytes(signed[1], 64) }
}

export async function verifySignedEnrollmentRequest(signed: SignedEnrollmentRequest): Promise<boolean> {
  return verifyDomain(DOMAINS.enrollmentRequest, encodeEnrollmentRequest(signed.request), signed.signature, signed.request.signingPublicKey)
}

interface ApprovalState {
  readonly fingerprint: Uint8Array
  readonly revision: SignedCapabilityRevision | null
  readonly target: EnrollmentFinalTarget | null
  readonly approval: SignedEnrollmentApproval | null
}

/** Live enrollment composes the same signed governance operations used by peers. */
export interface EnrollmentIssuerOptions {
  readonly descriptor: EnrollmentDescriptor
  readonly governance: GovernanceControlPlane
  readonly store: DurableOperationStore
  readonly rootPrivateKey: CryptoKey
  readonly captureFinalTarget: () => Promise<EnrollmentFinalTarget>
}

export class EnrollmentIssuer {
  readonly #options: EnrollmentIssuerOptions
  readonly #mutex: Mutex

  constructor(options: EnrollmentIssuerOptions) { this.#options = options; this.#mutex = storeLock(options.store) }

  async approve(signed: SignedEnrollmentRequest, decision: {
    readonly operationId: string
    readonly roles: readonly EnrollmentRole[]
    readonly grantFullHistory: boolean
    readonly writerProgram?: ProgramRights
  }): Promise<SignedEnrollmentApproval> {
    validateOperationId(decision.operationId)
    await verifyEnrollmentDescriptor(this.#options.descriptor)
    const request = signed.request
    const grantedRoles = roles(decision.roles)
    if (!await verifySignedEnrollmentRequest(signed) || !equalBytes(request.groupId, this.#options.descriptor.history.groupId) ||
        !equalBytes(request.genesisDigest, this.#options.descriptor.history.genesisDigest) ||
        !equalBytes(request.policyDigest, await historyConfigurationDigest(this.#options.descriptor.history)) ||
        !equalBytes(request.executionManifestDigest, this.#options.descriptor.history.executionManifestDigest) ||
        grantedRoles.some((role) => !request.requestedRoles.includes(role)) ||
        (decision.writerProgram !== undefined && !grantedRoles.includes('writer')) ||
        (grantedRoles.includes('writer') && !programRightsSubset(decision.writerProgram, request.writerProgram))) throw new Error('ENROLLMENT_REQUEST_UNAUTHORIZED')
    const requestBytes = encodeSignedEnrollmentRequest(signed)
    const requestDigest = await hashDomain(DOMAINS.enrollmentRequest, requestBytes)
    const fingerprint = encodeCanonicalCbor([requestBytes, grantedRoles, decision.grantFullHistory, rightsValue(decision.writerProgram)])
    const prefix = `enrollment/issuer/${bytesToHex(request.groupId)}`
    const key = `${prefix}/request/${bytesToHex(request.signingPublicKey)}/${encodeURIComponent(request.requestId)}`
    const operationKey = `${prefix}/operation/${encodeURIComponent(decision.operationId)}`
    const operationId = `enrollment:${bytesToHex(requestDigest)}`
    return this.#mutex.run(async () => {
      const priorOperation = await this.#options.store.get(operationKey)
      if (priorOperation !== null && !equalBytes(priorOperation, fingerprint)) throw new Error('OPERATION_ID_CONFLICT')
      let state = decodeApprovalState(await this.#options.store.get(key))
      if (state !== null && !equalBytes(state.fingerprint, fingerprint)) throw new Error('ENROLLMENT_DECISION_CONFLICT')
      await this.#options.store.put(operationKey, fingerprint)
      if (state === null) {
        state = { fingerprint, revision: null, target: null, approval: null }
        await this.#options.store.put(key, encodeApprovalState(state))
      }
      if (state.approval !== null) return state.approval
      if (state.revision === null) {
        const grants: Omit<CapabilityGrant, 'validFromRevision'>[] = grantedRoles.map((role) => ({
          subjectId: request.signingPublicKey, signingPublicKey: request.signingPublicKey,
          role, transportAuthor: request.transportAuthor,
          ...(role === 'reader' ? { hpkePublicKey: request.readerPublicKey } : {}),
          ...(role !== 'writer' || decision.writerProgram === undefined ? {} : { program: normalizeProgramRights(decision.writerProgram) }),
        }))
        const revision = await this.#options.governance.publishCapabilityChange({ grants }, this.#options.rootPrivateKey, { operationId: `${operationId}:grants` })
        state = { ...state, revision }
        await this.#options.store.put(key, encodeApprovalState(state))
      }
      if (this.#options.governance.currentEpoch === null) {
        await this.#options.governance.rotateEpoch(this.#options.rootPrivateKey, undefined, { operationId: `${operationId}:initial-epoch` })
      }
      if (decision.grantFullHistory) {
        await this.#options.governance.grantHistoricalAccess(request.signingPublicKey, this.#options.rootPrivateKey, { operationId: `${operationId}:history` })
      }
      if (state.target === null) {
        const captured = await this.#options.captureFinalTarget()
        if (!equalBytes(captured.executionManifestDigest, request.executionManifestDigest)) throw new Error('ENROLLMENT_ENGINE_MISMATCH')
        const target = { ...captured, requiredEpochs: uniqueEpochs([...captured.requiredEpochs, ...this.#options.governance.knownEpochs]) }
        state = { ...state, target }
        await this.#options.store.put(key, encodeApprovalState(state))
      }
      const revision = state.revision!
      const approval: EnrollmentApproval = {
        requestId: request.requestId, requestDigest, groupId: request.groupId,
        membershipRevision: await capabilityRevisionDigest(revision.revision), grantedRevision: revision.revision.revision,
        roles: grantedRoles, capabilityIds: await Promise.all(revision.revision.grants.map(capabilityId)),
        fullHistoryGranted: decision.grantFullHistory, target: state.target!,
        ...(decision.writerProgram === undefined ? {} : { writerProgram: normalizeProgramRights(decision.writerProgram) }),
      }
      const result = { approval, signature: await signDomain(DOMAINS.enrollmentApproval, encodeEnrollmentApproval(approval), this.#options.rootPrivateKey) }
      await this.#options.store.put(key, encodeApprovalState({ ...state, approval: result }))
      return result
    })
  }
}

export type EnrollmentState = 'requested' | 'approved' | 'authorized-disconnected' | 'awaiting-keys' | 'awaiting-history' | 'unsupported-engine' | 'revoked' | 'ready'
export interface EnrollmentProgress {
  readonly state: EnrollmentState
  readonly missingEpochs: readonly bigint[]
  readonly roles: readonly EnrollmentRole[]
}

/** Readiness is evidence about this replica, never inferred from a grant alone. */
export async function enrollmentProgress(options: {
  readonly descriptor: EnrollmentDescriptor
  readonly request: SignedEnrollmentRequest
  readonly approval: SignedEnrollmentApproval | null
  readonly activeMembership: CapabilitySnapshot
  readonly connected: boolean
  readonly availableEpochs: readonly bigint[]
  readonly executionManifestDigest: Uint8Array
  readonly isFinalTargetApplied: (target: EnrollmentFinalTarget) => boolean | Promise<boolean>
}): Promise<EnrollmentProgress> {
  const progress = (state: EnrollmentState, missingEpochs: readonly bigint[] = [], granted: readonly EnrollmentRole[] = []): EnrollmentProgress =>
    ({ state, missingEpochs, roles: granted })
  if (options.approval === null) return progress('requested')
  const { approval } = options.approval
  const request = options.request.request
  await verifyEnrollmentApproval(options.descriptor, options.request, options.approval)
  if (!equalBytes(options.activeMembership.groupId, request.groupId)) throw new Error('ENROLLMENT_MEMBERSHIP_GROUP_MISMATCH')
  if (options.activeMembership.revision < approval.grantedRevision) return progress('approved', [], approval.roles)
  for (let i = 0; i < approval.capabilityIds.length; i += 1) {
    const capability = options.activeMembership.capabilities.get(bytesToHex(approval.capabilityIds[i]!))
    if (capability === undefined || capability.grant.role !== approval.roles[i] ||
        !equalBytes(capability.grant.subjectId, request.signingPublicKey) ||
        !equalBytes(capability.grant.signingPublicKey, request.signingPublicKey) ||
        capability.grant.transportAuthor !== request.transportAuthor ||
        capability.grant.validFromRevision !== approval.grantedRevision ||
        capability.grantedAtRevision !== approval.grantedRevision ||
        (capability.grant.role === 'writer' && !equalBytes(encodeCanonicalCbor(rightsValue(capability.grant.program)), encodeCanonicalCbor(rightsValue(approval.writerProgram)))) ||
        (capability.grant.role === 'reader' && (capability.grant.hpkePublicKey === undefined ||
          !equalBytes(capability.grant.hpkePublicKey, request.readerPublicKey)))) throw new Error('ENROLLMENT_APPROVAL_INVALID')
    if (!isCapabilityActive(capability, options.activeMembership.revision)) return progress('revoked', [], approval.roles)
  }
  if (!options.connected) return progress('authorized-disconnected', [], approval.roles)
  if (!equalBytes(options.executionManifestDigest, approval.target.executionManifestDigest)) return progress('unsupported-engine', [], approval.roles)
  const available = new Set(options.availableEpochs.map(String))
  const missing = approval.target.requiredEpochs.filter((epoch) => !available.has(String(epoch)))
  if (!approval.fullHistoryGranted || missing.length > 0) return progress('awaiting-keys', missing, approval.roles)
  if (!await options.isFinalTargetApplied(approval.target)) return progress('awaiting-history', [], approval.roles)
  return progress('ready', [], approval.roles)
}

export async function verifyEnrollmentApproval(descriptor: EnrollmentDescriptor, signedRequest: SignedEnrollmentRequest, signed: SignedEnrollmentApproval): Promise<void> {
  const { approval, signature } = signed
  const request = signedRequest.request
  if (!await verifyDomain(DOMAINS.enrollmentApproval, encodeEnrollmentApproval(approval), signature, descriptor.genesis.manifest.rootAdminPublicKey) ||
      !await verifySignedEnrollmentRequest(signedRequest) || approval.requestId !== request.requestId ||
      !equalBytes(approval.groupId, request.groupId) || !equalBytes(request.groupId, descriptor.history.groupId) ||
      !equalBytes(request.genesisDigest, descriptor.history.genesisDigest) ||
      !equalBytes(request.policyDigest, await historyConfigurationDigest(descriptor.history)) ||
      !equalBytes(approval.target.executionManifestDigest, request.executionManifestDigest) ||
      approval.roles.some((role) => !request.requestedRoles.includes(role)) ||
      (approval.roles.includes('writer') && !programRightsSubset(approval.writerProgram, request.writerProgram)) ||
      !equalBytes(approval.requestDigest, await hashDomain(DOMAINS.enrollmentRequest, encodeSignedEnrollmentRequest(signedRequest)))) {
    throw new Error('ENROLLMENT_APPROVAL_INVALID')
  }
}

export function encodeEnrollmentApproval(approval: EnrollmentApproval): Uint8Array {
  validateOperationId(approval.requestId)
  if (approval.capabilityIds.length !== approval.roles.length || approval.grantedRevision < 1n) throw new Error('ENROLLMENT_APPROVAL_INVALID')
  if (approval.writerProgram !== undefined && !approval.roles.includes('writer')) throw new Error('ENROLLMENT_PROGRAM_WITHOUT_WRITER')
  for (const id of [approval.requestDigest, approval.groupId, approval.membershipRevision, ...approval.capabilityIds]) {
    if (id.length !== 32) throw new Error('ENROLLMENT_APPROVAL_INVALID')
  }
  return encodeCanonicalCbor([
    2n, approval.requestId, approval.requestDigest, approval.groupId, approval.membershipRevision,
    approval.grantedRevision, roles(approval.roles), [...approval.capabilityIds], approval.fullHistoryGranted, targetValue(approval.target), rightsValue(approval.writerProgram),
  ])
}

export function encodeSignedEnrollmentApproval(signed: SignedEnrollmentApproval): Uint8Array {
  if (signed.signature.length !== 64) throw new Error('ENROLLMENT_APPROVAL_INVALID')
  return encodeCanonicalCbor([encodeEnrollmentApproval(signed.approval), signed.signature])
}

export function decodeSignedEnrollmentApproval(encoded: Uint8Array): SignedEnrollmentApproval {
  const signed = array(encoded, 2)
  const value = array(bytes(signed[0]), 11)
  if (value[0] !== 2n || typeof value[5] !== 'bigint' || !Array.isArray(value[7]) || typeof value[8] !== 'boolean') {
    throw new Error('ENROLLMENT_APPROVAL_INVALID')
  }
  const approval: EnrollmentApproval = {
    requestId: string(value[1]), requestDigest: bytes(value[2], 32), groupId: bytes(value[3], 32), membershipRevision: bytes(value[4], 32),
    grantedRevision: value[5], roles: rolesValue(value[6]), capabilityIds: (value[7] as readonly CborValue[]).map((id) => bytes(id, 32)),
    fullHistoryGranted: value[8], target: targetFromValue(value[9]),
    ...(value[10] === null ? {} : { writerProgram: rightsFromValue(value[10]) }),
  }
  if (!equalBytes(encodeEnrollmentApproval(approval), bytes(signed[0]))) throw new Error('ENROLLMENT_APPROVAL_INVALID')
  return { approval, signature: bytes(signed[1], 64) }
}

function encodeApprovalState(state: ApprovalState): Uint8Array {
  return encodeCanonicalCbor([
    1n, state.fingerprint, state.revision === null ? null : encodeSignedCapabilityRevision(state.revision),
    state.target === null ? null : targetValue(state.target), state.approval === null ? null : encodeSignedEnrollmentApproval(state.approval),
  ])
}
function decodeApprovalState(encoded: Uint8Array | null): ApprovalState | null {
  if (encoded === null) return null
  const value = array(encoded, 5)
  if (value[0] !== 1n) throw new Error('ENROLLMENT_STATE_INVALID')
  return {
    fingerprint: bytes(value[1]), revision: value[2] === null ? null : decodeSignedCapabilityRevision(bytes(value[2])),
    target: value[3] === null ? null : targetFromValue(value[3]), approval: value[4] === null ? null : decodeSignedEnrollmentApproval(bytes(value[4])),
  }
}
function targetValue(target: EnrollmentFinalTarget): CborValue {
  if (target.frontier.length === 0 || target.executionManifestDigest.length !== 32) throw new Error('ENROLLMENT_TARGET_INVALID')
  return [target.frontier, uniqueEpochs(target.requiredEpochs), target.executionManifestDigest]
}
function targetFromValue(value: CborValue | undefined): EnrollmentFinalTarget {
  if (!Array.isArray(value) || value.length !== 3 || !Array.isArray(value[1]) || !value[1].every((item) => typeof item === 'bigint')) {
    throw new Error('ENROLLMENT_TARGET_INVALID')
  }
  const fields = value as readonly CborValue[]
  const epochs: bigint[] = []
  for (const epoch of fields[1] as readonly CborValue[]) {
    if (typeof epoch !== 'bigint') throw new Error('ENROLLMENT_TARGET_INVALID')
    epochs.push(epoch)
  }
  const target = { frontier: bytes(fields[0]), requiredEpochs: uniqueEpochs(epochs), executionManifestDigest: bytes(fields[2], 32) }
  targetValue(target)
  return target
}
function uniqueEpochs(values: readonly bigint[]): bigint[] {
  if (values.some((epoch) => epoch < 0n)) throw new Error('ENROLLMENT_TARGET_INVALID')
  return [...new Set(values)].sort((a, b) => a < b ? -1 : a > b ? 1 : 0)
}
function roles(values: readonly EnrollmentRole[]): EnrollmentRole[] {
  if (!values.includes('reader') || values.some((role) => role !== 'reader' && role !== 'writer') || new Set(values).size !== values.length) {
    throw new Error('ENROLLMENT_ROLES_INVALID')
  }
  return values.includes('writer') ? ['reader', 'writer'] : ['reader']
}
function rolesValue(value: CborValue | undefined): EnrollmentRole[] {
  if (!Array.isArray(value) || !value.every((role) => role === 'reader' || role === 'writer')) throw new Error('ENROLLMENT_ROLES_INVALID')
  return roles(value as EnrollmentRole[])
}
function array(encoded: Uint8Array, length: number): readonly CborValue[] {
  const value = assertCanonicalCbor(encoded)
  if (!Array.isArray(value) || value.length !== length) throw new Error('ENROLLMENT_ENCODING_INVALID')
  return value as readonly CborValue[]
}
function bytes(value: CborValue | undefined, length?: number): Uint8Array {
  if (!(value instanceof Uint8Array) || (length !== undefined && value.length !== length)) throw new Error('ENROLLMENT_ENCODING_INVALID')
  return value
}
function string(value: CborValue | undefined): string {
  if (typeof value !== 'string') throw new Error('ENROLLMENT_ENCODING_INVALID')
  return value
}

function rightsValue(input?: ProgramRights): CborValue {
  if (input === undefined) return null
  const rights = normalizeProgramRights(input)
  return [rights.sql, rights.topics, rights.signals, rights.forwarded]
}
function rightsFromValue(value: CborValue | undefined): ProgramRights {
  if (!Array.isArray(value) || value.length !== 4 || typeof value[0] !== 'boolean' || typeof value[3] !== 'boolean' ||
      !Array.isArray(value[1]) || !value[1].every((item) => typeof item === 'string') ||
      !Array.isArray(value[2]) || !value[2].every((item) => typeof item === 'string')) throw new Error('ENROLLMENT_PROGRAM_INVALID')
  return normalizeProgramRights({ sql: value[0], topics: value[1], signals: value[2], forwarded: value[3] })
}
