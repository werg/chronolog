import {
  capabilityId, capabilityRevisionDigest, decodeSignedCapabilityRevision, encodeCapabilityRevision,
  encodeSignedCapabilityRevision, programAllowed, validationPolicyId,
  type SignedCapabilityRevision,
} from '@chronolog/capabilities'
import {
  DOMAINS, assertCanonicalCbor, assertEventTopic, bytesToHex, decodeTransactionCore, emit,
  encodeCanonicalCbor, encodeChangeProgram, decodeChangeProgram, encodeTransactionCore, equalBytes, exportEd25519PrivateKey,
  generateEd25519KeyPair, hashDomain, importEd25519PrivateKey, importEd25519PublicKey, isEmitStep,
  program, signDomain, transactionDigest, verifyDomain,
  type ChangeProgram, type Ed25519KeyPair, type EventPayload, type TransactionCore,
} from '@chronolog/protocol'
import { Mutex } from './async.js'
import { verifyEnrollmentDescriptor, type EnrollmentDescriptor } from './enrollment.js'
import type { GovernanceControlPlane } from './governance.js'
import { historyConfigurationDigest } from './history-policy.js'
import { DurableOperationJournal, validateOperationId, type DurableOperationStore } from './operations.js'
import { decodeSignedMessage, signWireMessage } from './wire.js'

/** A separate enrollment path: no reader role, HPKE key or history target. */
export interface PublisherRequest {
  readonly requestId: string
  readonly groupId: Uint8Array
  readonly historyDigest: Uint8Array
  readonly signer: Uint8Array
  readonly topics: readonly string[]
  readonly signals: readonly string[]
}
export interface SignedPublisherRequest { readonly request: PublisherRequest; readonly signature: Uint8Array }
export interface PublisherApproval {
  readonly requestDigest: Uint8Array
  readonly revision: SignedCapabilityRevision
  readonly validationPolicy: Uint8Array
  readonly signature: Uint8Array
}
const locks = new WeakMap<DurableOperationStore, Mutex>()
function lock(store: DurableOperationStore): Mutex {
  let mutex = locks.get(store)
  if (mutex === undefined) { mutex = new Mutex(); locks.set(store, mutex) }
  return mutex
}
function scopes(values: readonly string[]): readonly string[] {
  const input: unknown = values
  if (!Array.isArray(input) || values.length > 128) throw new Error('PUBLISHER_SCOPES_INVALID')
  values.forEach(assertEventTopic)
  return [...new Set(values)].sort()
}
function requestBody(request: PublisherRequest): Uint8Array {
  validateOperationId(request.requestId)
  if ([request.groupId, request.historyDigest, request.signer].some((value) => value.length !== 32)) throw new Error('PUBLISHER_REQUEST_INVALID')
  return encodeCanonicalCbor([1n, request.requestId, request.groupId, request.historyDigest, request.signer, scopes(request.topics), scopes(request.signals)])
}
export function encodePublisherRequest(signed: SignedPublisherRequest): Uint8Array {
  if (signed.signature.length !== 64) throw new Error('PUBLISHER_REQUEST_INVALID')
  return encodeCanonicalCbor([requestBody(signed.request), signed.signature])
}
export function decodePublisherRequest(bytes: Uint8Array): SignedPublisherRequest {
  const value = assertCanonicalCbor(bytes)
  if (!Array.isArray(value) || value.length !== 2 || !(value[0] instanceof Uint8Array) || !(value[1] instanceof Uint8Array)) throw new Error('PUBLISHER_REQUEST_INVALID')
  const body = assertCanonicalCbor(value[0])
  if (!Array.isArray(body) || body.length !== 7 || body[0] !== 1n || typeof body[1] !== 'string' ||
      !(body[2] instanceof Uint8Array) || !(body[3] instanceof Uint8Array) || !(body[4] instanceof Uint8Array) ||
      !Array.isArray(body[5]) || !body[5].every((item) => typeof item === 'string') ||
      !Array.isArray(body[6]) || !body[6].every((item) => typeof item === 'string')) throw new Error('PUBLISHER_REQUEST_INVALID')
  const result = { request: { requestId: body[1], groupId: body[2], historyDigest: body[3], signer: body[4],
    topics: body[5], signals: body[6] }, signature: value[1] }
  if (!equalBytes(encodePublisherRequest(result), bytes)) throw new Error('PUBLISHER_REQUEST_INVALID')
  return result
}

export async function loadOrCreatePublisherIdentity(store: DurableOperationStore, namespace: string): Promise<Ed25519KeyPair> {
  validateOperationId(namespace)
  return lock(store).run(async () => {
    const key = `publisher/identity/${encodeURIComponent(namespace)}`
    let bytes = await store.get(key)
    if (bytes === null) {
      const pair = await generateEd25519KeyPair()
      bytes = encodeCanonicalCbor([1n, pair.publicKeyBytes, await exportEd25519PrivateKey(pair.privateKey)])
      await store.put(key, bytes)
    }
    const value = assertCanonicalCbor(bytes)
    if (!Array.isArray(value) || value.length !== 3 || value[0] !== 1n ||
        !(value[1] instanceof Uint8Array) || value[1].length !== 32 || !(value[2] instanceof Uint8Array)) throw new Error('PUBLISHER_IDENTITY_INVALID')
    return { publicKeyBytes: value[1], publicKey: await importEd25519PublicKey(value[1]), privateKey: await importEd25519PrivateKey(value[2]) }
  })
}

export async function preparePublisherRequest(options: {
  readonly descriptor: EnrollmentDescriptor; readonly store: DurableOperationStore; readonly identity: Ed25519KeyPair
  readonly requestId: string; readonly topics: readonly string[]; readonly signals?: readonly string[]
}): Promise<SignedPublisherRequest> {
  await verifyEnrollmentDescriptor(options.descriptor)
  const request: PublisherRequest = { requestId: options.requestId, groupId: options.descriptor.history.groupId,
    historyDigest: await historyConfigurationDigest(options.descriptor.history), signer: options.identity.publicKeyBytes,
    topics: scopes(options.topics), signals: scopes(options.signals ?? []) }
  const body = requestBody(request)
  return lock(options.store).run(async () => {
    const key = `publisher/request/${bytesToHex(request.groupId)}/${encodeURIComponent(request.requestId)}`
    const saved = await options.store.get(key)
    if (saved !== null) {
      const result = decodePublisherRequest(saved)
      if (!equalBytes(requestBody(result.request), body)) throw new Error('PUBLISHER_REQUEST_ID_CONFLICT')
      return result
    }
    const signed = { request, signature: await signDomain(DOMAINS.publisherRequest, body, options.identity.privateKey) }
    await options.store.put(key, encodePublisherRequest(signed))
    return signed
  })
}
function approvalBody(value: Omit<PublisherApproval, 'signature'>): Uint8Array {
  return encodeCanonicalCbor([1n, value.requestDigest, encodeSignedCapabilityRevision(value.revision), value.validationPolicy])
}
export function encodePublisherApproval(value: PublisherApproval): Uint8Array { return encodeCanonicalCbor([approvalBody(value), value.signature]) }
export function decodePublisherApproval(bytes: Uint8Array): PublisherApproval {
  const signed = assertCanonicalCbor(bytes)
  if (!Array.isArray(signed) || signed.length !== 2 || !(signed[0] instanceof Uint8Array) || !(signed[1] instanceof Uint8Array) || signed[1].length !== 64) throw new Error('PUBLISHER_APPROVAL_INVALID')
  const value = assertCanonicalCbor(signed[0])
  if (!Array.isArray(value) || value.length !== 4 || value[0] !== 1n || !(value[1] instanceof Uint8Array) || value[1].length !== 32 ||
      !(value[2] instanceof Uint8Array) || !(value[3] instanceof Uint8Array) || value[3].length !== 32) throw new Error('PUBLISHER_APPROVAL_INVALID')
  return { requestDigest: value[1], revision: decodeSignedCapabilityRevision(value[2]), validationPolicy: value[3], signature: signed[1] }
}

/** Issue a scoped writer grant through ordinary governance, without key delivery. */
export async function approvePublisherRequest(options: {
  readonly descriptor: EnrollmentDescriptor; readonly governance: GovernanceControlPlane
  readonly store: DurableOperationStore; readonly rootPrivateKey: CryptoKey
  readonly request: SignedPublisherRequest; readonly topics: readonly string[]; readonly signals?: readonly string[]
}): Promise<PublisherApproval> {
  await verifyEnrollmentDescriptor(options.descriptor)
  const { request } = options.request
  const topics = scopes(options.topics), signals = scopes(options.signals ?? [])
  if (!equalBytes(request.groupId, options.descriptor.history.groupId) ||
      !equalBytes(request.historyDigest, await historyConfigurationDigest(options.descriptor.history)) ||
      !await verifyDomain(DOMAINS.publisherRequest, requestBody(request), options.request.signature, request.signer) ||
      topics.some((topic) => !request.topics.includes(topic)) || signals.some((topic) => !request.signals.includes(topic))) throw new Error('PUBLISHER_REQUEST_UNAUTHORIZED')
  const signedRequest = encodePublisherRequest(options.request)
  const requestDigest = await hashDomain(DOMAINS.publisherRequest, signedRequest)
  const fingerprint = encodeCanonicalCbor([signedRequest, topics, signals])
  return lock(options.store).run(async () => {
    const key = `publisher/issued/${bytesToHex(request.groupId)}/${bytesToHex(request.signer)}/${encodeURIComponent(request.requestId)}`
    const saved = await options.store.get(key)
    if (saved !== null) {
      const state = assertCanonicalCbor(saved)
      if (!Array.isArray(state) || state.length !== 2 || !(state[0] instanceof Uint8Array) || !equalBytes(state[0], fingerprint)) throw new Error('PUBLISHER_DECISION_CONFLICT')
      if (state[1] instanceof Uint8Array) return decodePublisherApproval(state[1])
      if (state[1] !== null) throw new Error('PUBLISHER_APPROVAL_INVALID')
    } else await options.store.put(key, encodeCanonicalCbor([fingerprint, null]))
    const revision = await options.governance.publishCapabilityChange({ grants: [{
      role: 'writer', subjectId: request.signer, signingPublicKey: request.signer,
      program: { sql: false, topics, signals, forwarded: true },
    }] }, options.rootPrivateKey, { operationId: `publisher:${bytesToHex(requestDigest)}` })
    const body = { requestDigest, revision, validationPolicy: await validationPolicyId(options.descriptor.genesis.manifest.validationPolicies[0]!) }
    const approval = { ...body, signature: await signDomain(DOMAINS.publisherApproval, approvalBody(body), options.rootPrivateKey) }
    await options.store.put(key, encodeCanonicalCbor([fingerprint, encodePublisherApproval(approval)]))
    return approval
  })
}

export async function verifyPublisherApproval(descriptor: EnrollmentDescriptor, request: SignedPublisherRequest, approval: PublisherApproval): Promise<void> {
  await verifyEnrollmentDescriptor(descriptor)
  const root = descriptor.genesis.manifest.rootAdminPublicKey
  const revision = approval.revision.revision, grant = revision.grants[0]
  if (!await verifyDomain(DOMAINS.publisherRequest, requestBody(request.request), request.signature, request.request.signer) ||
      !equalBytes(request.request.groupId, descriptor.history.groupId) ||
      !equalBytes(request.request.historyDigest, await historyConfigurationDigest(descriptor.history)) ||
      !equalBytes(approval.requestDigest, await hashDomain(DOMAINS.publisherRequest, encodePublisherRequest(request))) ||
      !await verifyDomain(DOMAINS.publisherApproval, approvalBody(approval), approval.signature, root) ||
      !await verifyDomain(DOMAINS.capabilityRevision, encodeCapabilityRevision(revision), approval.revision.signature, root) ||
      !equalBytes(revision.groupId, descriptor.history.groupId) || !equalBytes(revision.issuerRootPublicKey, root) ||
      revision.grants.length !== 1 || grant === undefined || grant.role !== 'writer' || grant.hpkePublicKey !== undefined ||
      !equalBytes(grant.subjectId, request.request.signer) || !equalBytes(grant.signingPublicKey, request.request.signer) ||
      grant.program?.sql !== false || grant.program.forwarded !== true ||
      grant.program.topics.some((topic) => !request.request.topics.includes(topic)) || grant.program.signals.some((topic) => !request.request.signals.includes(topic))) {
    throw new Error('PUBLISHER_APPROVAL_INVALID')
  }
}

export interface PublisherReceipt { readonly operationId: string; readonly proposalId: string }
/** Durable original-signer outbox. A receipt means submitted, never final. */
export async function createLimitedPublisher(options: {
  readonly descriptor: EnrollmentDescriptor; readonly request: SignedPublisherRequest; readonly approval: PublisherApproval
  readonly identity: Ed25519KeyPair; readonly store: DurableOperationStore
  readonly send: (signed: Uint8Array) => Promise<{ readonly txIdText?: string; readonly proposalId?: string }>
  readonly now?: () => number
}) {
  await verifyPublisherApproval(options.descriptor, options.request, options.approval)
  if (!equalBytes(options.identity.publicKeyBytes, options.request.request.signer)) throw new Error('PUBLISHER_IDENTITY_MISMATCH')
  const grant = options.approval.revision.revision.grants[0]!
  const writerCapability = await capabilityId(grant)
  const membershipRevision = await capabilityRevisionDigest(options.approval.revision.revision)
  const journal = new DurableOperationJournal(options.store, `publisher/outbox/${bytesToHex(options.descriptor.history.groupId)}/${bytesToHex(options.identity.publicKeyBytes)}`)
  const send = async (signed: Uint8Array): Promise<void> => {
    const wire = await decodeSignedMessage(signed)
    const expected = `tx_${bytesToHex(await transactionDigest(wire.payload))}`
    const receipt = await options.send(signed)
    if ((receipt.proposalId ?? receipt.txIdText) !== expected) throw new Error('PUBLISHER_RECEIPT_MISMATCH')
  }
  const submit = async (change: ChangeProgram, input: { readonly operationId: string }): Promise<PublisherReceipt> => {
    const fingerprint = encodeChangeProgram(change)
    change = decodeChangeProgram(fingerprint)
    const signed = await journal.run({ operationId: input.operationId, fingerprint,
      prepare: async () => {
        if (!change.steps.every(isEmitStep) || !programAllowed(grant, change)) throw new Error('PUBLISHER_PROGRAM_UNAUTHORIZED')
        const core: TransactionCore = { operationId: input.operationId, groupId: options.descriptor.history.groupId,
          membershipRevision, validationPolicy: options.approval.validationPolicy, writerCapability,
          authorId: options.identity.publicKeyBytes, authorTimestampMs: BigInt(Math.trunc((options.now ?? Date.now)())),
          nonce: crypto.getRandomValues(new Uint8Array(32)), executionManifestDigest: options.descriptor.history.executionManifestDigest,
          program: change }
        return signWireMessage('candidate', encodeTransactionCore(core), options.identity)
      }, apply: send })
    const wire = await decodeSignedMessage(signed)
    return { operationId: decodeTransactionCore(wire.payload).operationId, proposalId: `tx_${bytesToHex(await transactionDigest(wire.payload))}` }
  }
  return { submit,
    publish: (topic: string, payload: EventPayload, input: { readonly operationId: string }) => submit(program(emit(topic, payload)), input),
    recover: () => journal.recover(send),
  }
}
