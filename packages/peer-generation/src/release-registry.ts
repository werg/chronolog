import { DOMAINS } from '@chronolog/protocol'
import {
  check, decodePeerValue, encodePeerValue, hex, isArray, object, peerDigest,
  samePeerValue, Serial, signPeerValue,
} from './codec.js'
import type { BytesStore } from '@chronolog/records'
import {
  RELEASE_LIMITS, RELEASE_PROFILE, type ReleasePolicyRequest, type ReleaseRegistry, type ReleaseRegistryOptions,
  type ReleaseState, type SignedReleaseActivation, type SignedReleaseActivationRequest, type SignedReleaseManifest,
} from './release-types.js'
import {
  assertReleaseStateExtension, signReleasePolicy, validateReleaseActivationRequest, validateReleaseApplicationBinding,
  validateReleaseManifest, validateReleasePolicyRequest, verifyReleaseActivationRequest,
  verifyReleaseContent, verifyReleaseManifest, verifyReleaseState,
} from './release-verify.js'

interface Head { readonly version: 1; readonly state: ReleaseState; readonly publications: readonly string[] }
interface Owner { readonly serial: Serial; pending: number; pendingPolicy: number }
const owners = new WeakMap<BytesStore, Map<string, Owner>>()
function ownerFor(store: BytesStore, key: string): Owner {
  let values = owners.get(store)
  if (values === undefined) { values = new Map(); owners.set(store, values) }
  let owner = values.get(key)
  if (owner === undefined) { owner = { serial: new Serial(), pending: 0, pendingPolicy: 0 }; values.set(key, owner) }
  return owner
}

/**
 * A control/content participant with no SQL replica or application decryption key.
 * The store has one exclusive durable owner. Content is immutable, and its adapter
 * must retain published references atomically with acknowledged manifest storage.
 */
export async function createReleaseRegistry(options: ReleaseRegistryOptions): Promise<ReleaseRegistry> {
  hex(options.applicationId); hex(options.signer.publicKey)
  const trust = { applicationId: options.applicationId, controlPublicKey: options.signer.publicKey }
  const prefix = `chronolog-release/${options.applicationId}`, headKey = `${prefix}/head`
  const owner = ownerFor(options.store, headKey)
  let observed: ReleaseState | undefined
  const read = async (): Promise<Head> => {
    const bytes = await options.store.get(headKey); check(bytes !== null, 'RELEASE_STATE_MISSING')
    const value = decodePeerValue<Head>(bytes); object(value, ['version', 'state', 'publications'])
    check(value.version === 1, 'RELEASE_STATE_INVALID')
    const state = await verifyReleaseState(value.state, trust)
    if (observed !== undefined) assertReleaseStateExtension(observed, state)
    check(isArray(value.publications) && value.publications.length <= RELEASE_LIMITS.publications, 'RELEASE_PUBLICATION_LIMIT')
    const ids = new Set<string>()
    for (const id of value.publications) { hex(id); check(!ids.has(id), 'RELEASE_PUBLICATION_DUPLICATE'); ids.add(id) }
    check(state.activations.every(activation => ids.has(activation.payload.releaseId)), 'RELEASE_ACTIVATION_MANIFEST_MISSING')
    observed = state
    return { version: 1, state, publications: value.publications }
  }
  const save = async (head: Head): Promise<void> => {
    await verifyReleaseState(head.state, trust)
    if (observed !== undefined) assertReleaseStateExtension(observed, head.state)
    await options.store.put(headKey, encodePeerValue(head))
    observed = structuredClone(head.state)
  }
  const manifest = async (head: Head, id: string): Promise<SignedReleaseManifest | null> => {
    hex(id)
    if (!head.publications.includes(id)) return null
    const bytes = await options.store.get(`${prefix}/manifest/${id}`)
    check(bytes !== null && bytes.length <= RELEASE_LIMITS.manifestBytes + 1024, 'RELEASE_MANIFEST_MISSING')
    const value = decodePeerValue<SignedReleaseManifest>(bytes)
    const policy = head.state.policies[value.payload.policyRevision]
    check(policy !== undefined, 'RELEASE_POLICY_MISSING')
    check(await verifyReleaseManifest(value, policy, trust) === id, 'RELEASE_MANIFEST_ID_INVALID')
    return value
  }
  const admit = async <T>(action: () => Promise<T>, policy = false): Promise<T> => {
    if (policy) {
      check(owner.pendingPolicy < 2, 'RELEASE_REQUEST_LIMIT'); owner.pendingPolicy++
      try { return await action() } finally { owner.pendingPolicy-- }
    }
    check(owner.pending < 8, 'RELEASE_REQUEST_LIMIT'); owner.pending++
    try { return await action() } finally { owner.pending-- }
  }
  const currentPolicy = (head: Head) => {
    const value = head.state.policies.at(-1); check(value !== undefined, 'RELEASE_POLICY_MISSING'); return value
  }
  const authorizePublication = async (head: Head, value: SignedReleaseManifest): Promise<void> => {
    const policy = currentPolicy(head)
    check(value.payload.policyRevision === policy.payload.revision, 'RELEASE_POLICY_CHANGED')
    await verifyReleaseManifest(value, policy, trust)
    check(head.publications.length < RELEASE_LIMITS.publications, 'RELEASE_PUBLICATION_LIMIT')
  }
  const priorActivation = (head: Head, request: SignedReleaseActivationRequest): SignedReleaseActivation | undefined => {
    const previous = head.state.activations.find(value => value.payload.request.payload.publisher === request.payload.publisher &&
      value.payload.request.payload.requestId === request.payload.requestId)
    if (previous !== undefined) check(samePeerValue(previous.payload.request, request), 'RELEASE_ACTIVATION_REQUEST_REUSED')
    return previous
  }
  const authorizeActivation = async (head: Head, request: SignedReleaseActivationRequest): Promise<void> => {
    const policy = currentPolicy(head)
    check(request.payload.policyRevision === policy.payload.revision, 'RELEASE_POLICY_CHANGED')
    await verifyReleaseActivationRequest(request, policy, trust)
    check(request.payload.expectedActivation === (head.state.activations.at(-1)?.id ?? null), 'RELEASE_ACTIVATION_CONFLICT')
    check(head.state.activations.length < RELEASE_LIMITS.activations, 'RELEASE_ACTIVATION_LIMIT')
  }
  const applicationMatches = async (value: SignedReleaseManifest): Promise<void> => {
    if (options.application === undefined) return
    const binding = await options.application()
    if (binding !== null) validateReleaseApplicationBinding(binding)
    check(samePeerValue(value.payload.application, binding), 'RELEASE_APPLICATION_BOUNDARY_REQUIRED')
  }
  await owner.serial.run(async () => {
    if (await options.store.get(headKey) === null) {
      check(options.requireExisting !== true, 'RELEASE_STATE_MISSING')
      await save({ version: 1, state: { ...trust, profile: RELEASE_PROFILE, policies: [], activations: [] }, publications: [] })
    }
    await read()
  })
  return {
    read: () => admit(() => owner.serial.run(async () => structuredClone((await read()).state))),
    async configure(input: ReleasePolicyRequest) {
      validateReleasePolicyRequest(input); const request = structuredClone(input)
      return admit(() => owner.serial.run(async () => {
        const head = await read(), prior = head.state.policies.find(policy => policy.payload.requestId === request.requestId)
        if (prior !== undefined) {
          check(prior.payload.previous === request.expectedPolicy && samePeerValue(prior.payload.publishers, request.publishers), 'RELEASE_POLICY_REQUEST_REUSED')
          return structuredClone(prior)
        }
        const policy = head.state.policies.at(-1), expected = policy === undefined ? null : await peerDigest(policy)
        check(expected === request.expectedPolicy, 'RELEASE_POLICY_CONFLICT')
        check(head.state.policies.length < RELEASE_LIMITS.policies, 'RELEASE_POLICY_LIMIT')
        const next = await signReleasePolicy({ profile: RELEASE_PROFILE, applicationId: options.applicationId, scope: 'page',
          revision: head.state.policies.length, previous: expected, requestId: request.requestId, publishers: request.publishers }, options.signer)
        await save({ ...head, state: { ...head.state, policies: [...head.state.policies, next] } })
        return structuredClone(next)
      }), true)
    },
    async publish(input: SignedReleaseManifest) {
      object(input, ['payload', 'signature']); validateReleaseManifest(input.payload); hex(input.signature, 64)
      const value = structuredClone(input)
      return admit(async () => {
        const id = await peerDigest(value)
        const previous = await owner.serial.run(async () => {
          const head = await read(), existing = await manifest(head, id)
          if (existing === null) await authorizePublication(head, value)
          return existing
        })
        if (previous !== null) return { id, manifest: previous }
        // Reading content cannot hold up publisher revocation. Recheck authority
        // after the last asynchronous read before making this manifest available.
        await verifyReleaseContent(value, options.content)
        return owner.serial.run(async () => {
          const head = await read(), existing = await manifest(head, id)
          if (existing !== null) return { id, manifest: existing }
          await authorizePublication(head, value)
          await options.store.put(`${prefix}/manifest/${id}`, encodePeerValue(value))
          await save({ ...head, publications: [...head.publications, id] })
          return { id, manifest: structuredClone(value) }
        })
      })
    },
    manifest: (id: string) => admit(() => owner.serial.run(async () => manifest(await read(), id))),
    async activate(input: SignedReleaseActivationRequest) {
      object(input, ['payload', 'signature']); validateReleaseActivationRequest(input.payload); hex(input.signature, 64)
      const request = structuredClone(input)
      return admit(async () => {
        const prepared = await owner.serial.run(async () => {
          const head = await read(), previous = priorActivation(head, request)
          if (previous !== undefined) return { previous }
          await authorizeActivation(head, request)
          const value = await manifest(head, request.payload.releaseId); check(value !== null, 'RELEASE_MANIFEST_MISSING')
          return { manifest: value }
        })
        if (prepared.previous !== undefined) return structuredClone(prepared.previous)
        const value = prepared.manifest
        await applicationMatches(value); await verifyReleaseContent(value, options.content)
        return owner.serial.run(async () => {
          const head = await read(), previous = priorActivation(head, request)
          if (previous !== undefined) return structuredClone(previous)
          await authorizeActivation(head, request); await applicationMatches(value)
          const policy = currentPolicy(head)
          const signed = await signPeerValue(DOMAINS.releaseActivation, { profile: RELEASE_PROFILE, applicationId: options.applicationId,
            revision: head.state.activations.length, previous: head.state.activations.at(-1)?.id ?? null,
            policyRevision: policy.payload.revision, policyDigest: await peerDigest(policy), releaseId: request.payload.releaseId, request }, options.signer)
          const activation = { ...signed, id: await peerDigest(signed) }
          // One atomic durable pointer selects code. Application generation
          // rollback and learned data permissions have no write path to this key.
          await save({ ...head, state: { ...head.state, activations: [...head.state.activations, activation] } })
          return structuredClone(activation)
        })
      })
    },
  }
}
