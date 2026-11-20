import { afterEach, describe, expect, it, vi } from 'vitest'
import {
  bytesDigest, createGenerationRegistry, createParticipantResponse, createPeerIdentity, createPublicationRegistry,
  MemoryBytesStore, participantGrant, signApplicationDescriptor, signControlRevision, signTransitionRequest,
  type AuthorityBundle, type ParticipantRequest, type SignedPublication, type SignedTransitionRequest,
} from '@chronolog/peer-generation'
import { eventExecutionManifest } from '@chronolog/materializer'
import { bytesToHex, emit, executionManifestArtifacts, program } from '@chronolog/protocol'
import { applicationDefinitionDigest, defineApplication, defineCommand, describeApplication } from './definition.js'
import { openApplicationDevice } from './device.js'
import { openPeerApplication } from './runtime.js'
import { connectApplications } from './session.js'
import { ApplicationPublicationError } from './control-participant.js'

const definition = defineApplication({ id: 'participant', version: '1', commands: {
  say: defineCommand({ description: 'Say', input: { type: 'string' }, prepare: text => program(emit('message', { text })) }),
}, queries: {} })
const cleanup: Array<() => void | Promise<void>> = []
afterEach(async () => { for (const close of cleanup.splice(0).reverse()) await close(); vi.restoreAllMocks() })

async function fixture() {
  const signer = await createPeerIdentity(), stores = [new MemoryBytesStore(), new MemoryBytesStore()]
  const storageOpens = [0, 0]
  const openDevice = (index: number, create = false) => openApplicationDevice({ store: stores[index]!,
    ...(create ? { create: true as const } : {}),
    openStorage() { storageOpens[index] = storageOpens[index]! + 1; return { store: stores[index]!, close() {} } },
  })
  const devices = await Promise.all(stores.map((_store, index) => openDevice(index, true)))
  const key = crypto.getRandomValues(new Uint8Array(32)), epochKeys = new Map([[0, key]])
  const manifest = await executionManifestArtifacts(await eventExecutionManifest())
  const descriptor = await signApplicationDescriptor({ applicationId: 'ab'.repeat(32), historyId: 'participant-test',
    profile: 'peer-generation-v1', policy: 'eligible-members-v1', controlPublicKey: signer.publicKey,
    schemaAdministrator: devices[0]!.identity.publicKey, definitionDigest: await applicationDefinitionDigest(definition),
    executionManifestDigest: bytesToHex(manifest.executionManifestDigest), schemaDigest: null }, signer)
  const control = await signControlRevision({ applicationId: descriptor.payload.applicationId, profile: descriptor.payload.profile,
    policy: descriptor.payload.policy, revision: 0, previous: null, epoch: 0, keyDigest: await bytesDigest(key), recoveryFloor: null,
    grants: devices.map(device => participantGrant(device.identity.publicKey, { administrator: true, publisher: true })) }, signer)
  const registry = await createGenerationRegistry({ store: new MemoryBytesStore(), descriptor, controls: [control], signer })
  await registry.select(await signTransitionRequest({ applicationId: descriptor.payload.applicationId, profile: descriptor.payload.profile,
    policy: descriptor.payload.policy, transitionId: 'initial', expectedGeneration: null, coordinator: devices[0]!.identity.publicKey,
    requester: devices[0]!.identity.publicKey, controlRevision: 0, reason: 'create', base: null }, devices[0]!.identity))
  const publications = await createPublicationRegistry({ store: new MemoryBytesStore(), authority: () => registry.read() })
  const traffic: ParticipantRequest[] = []
  const faults: { offline?: boolean; losePublication?: boolean; stalePublication?: SignedPublication; staleAuthority?: AuthorityBundle } = {}
  const exchange = async (request: ParticipantRequest) => {
    traffic.push(structuredClone(request))
    if (faults.offline === true) throw new Error('HOST_UNAVAILABLE')
    let result: unknown
    if (request.facet === 'control' && request.action === 'read') result = faults.staleAuthority ?? await registry.read()
    else if (request.facet === 'control' && request.action === 'select') result = await registry.select((request.payload as { request: SignedTransitionRequest }).request)
    else if (request.facet === 'publication' && request.action === 'definition') result = { descriptor, definition: describeApplication(definition), schema: null }
    else if (request.facet === 'publication' && request.action === 'read') {
      const records = await publications.read(), id = (request.payload as { id?: string }).id
      const publication = id === undefined ? faults.stalePublication ?? records.at(-1) : records.find(value => value.id === id)
      result = publication === undefined ? null : { publication, version: publication.payload.revision + 1 }
    } else if (request.facet === 'publication' && request.action === 'publish') {
      const publication = await publications.publish((request.payload as { publication: SignedPublication }).publication)
      if (faults.losePublication === true) { faults.losePublication = false; throw new Error('LOST_PUBLICATION_REPLY') }
      result = { publication, version: publication.payload.revision + 1 }
    } else throw new Error('UNEXPECTED_HOST_INTEREST')
    return createParticipantResponse(request, result)
  }
  const open = async (index: number, resume = false) => {
    const device = resume ? await openDevice(index) : devices[index]!
    const session = await openPeerApplication({ device, definition, authority: await registry.read(), epochKeys })
    cleanup.push(() => session.close())
    return session
  }
  return { open, registry, publications, exchange, traffic, faults, devices, storageOpens }
}

describe('session-owned control participant', () => {
  it('exchanges live signals and verified control/code before opening durable application data', async () => {
    const f = await fixture(), a = await f.open(0), b = await f.open(1)
    const control = a.connectControlParticipant({ exchange: f.exchange })
    const links = await connectApplications(a, b); cleanup.push(() => links.close())
    expect(a.status.database).toBe('idle'); expect(b.status.database).toBe('idle')
    expect(a.revision).toBeNull(); expect(b.revision).toBeNull()
    await control.application(); await control.definition(); expect(await control.publication()).toBeNull()
    const bytes = new TextEncoder().encode('<main>Protocol only</main>')
    const release = await control.preparePublication({ operationId: 'protocol-page', entry: 'index.html',
      files: [{ path: 'index.html', hash: await bytesDigest(bytes), size: bytes.length, type: 'text/html' }] })
    await control.publish(release, []); expect((await control.publication())?.publication.id).toBe(release.id)
    const iterator = a.signals.subscribe({ topics: ['typing'], signal: AbortSignal.timeout(5000) })[Symbol.asyncIterator]()
    const incoming = iterator.next(); await b.signals.send('typing', { active: true })
    expect((await incoming).value?.topic).toBe('typing'); await iterator.return?.()
    expect(f.storageOpens).toEqual([0, 0])
    const views = await Promise.all([a.readView(), a.readView()])
    for (const view of views) view.release()
    expect(f.storageOpens).toEqual([1, 0])
    expect(a.status.database).toBe('ready'); expect(b.status.database).toBe('idle')
  })

  it('drains a closing control participant journal before releasing the application session', async () => {
    const f = await fixture(), session = await f.open(0), control = session.connectControlParticipant({ exchange: f.exchange })
    const store = f.devices[0]!.store, put = store.put.bind(store)
    let writing = false, release!: () => void
    const gate = new Promise<void>(resolve => { release = resolve })
    vi.spyOn(store, 'put').mockImplementation(async (key, bytes) => {
      if (key.startsWith('peer-session/publication-attempt/')) { writing = true; await gate }
      await put(key, bytes)
    })
    const bytes = new TextEncoder().encode('export default 1;')
    const pending = control.preparePublication({ operationId: 'closing', entry: 'main.mjs',
      files: [{ path: 'main.mjs', hash: await bytesDigest(bytes), size: bytes.length, type: 'text/javascript' }] })
    const rejected = expect(pending).rejects.toThrow('APPLICATION_CONTROL_CLOSED')
    await vi.waitFor(() => { expect(writing).toBe(true) }, { timeout: 5000, interval: 5 })
    const controlClosed = control.close()
    let replacementError: unknown
    try { session.connectControlParticipant({ exchange: f.exchange }) } catch (error) { replacementError = error }
    let released = false
    const closed = session.close().then(() => { released = true })
    let releasedEarly: boolean
    try {
      await new Promise(resolve => setTimeout(resolve, 20))
      releasedEarly = released
    } finally { release(); await Promise.all([controlClosed, closed, rejected]) }
    expect(releasedEarly).toBe(false)
    expect(replacementError).toEqual(new Error('APPLICATION_CONTROL_ALREADY_ATTACHED'))
    expect(released).toBe(true)
  })

  it('attaches without I/O and keeps commands, data, and live signals off the host', async () => {
    const f = await fixture(), a = await f.open(0), b = await f.open(1)
    const host = a.connectControlParticipant({ exchange: f.exchange })
    expect(host.role).toBe('control'); expect(host.policy.role).toBe('control')
    expect(f.traffic).toEqual([]); expect(a.status.connectedPeers).toBe(0)
    expect(() => a.connectControlParticipant({ exchange: f.exchange })).toThrow('APPLICATION_CONTROL_ALREADY_ATTACHED')
    const links = await connectApplications(a, b)
    cleanup.push(() => links.close())
    f.faults.offline = true
    const operation = await b.command('say', 'ordinary work', { operationId: 'peer-only' })
    expect((await operation.applied({ signal: AbortSignal.timeout(5000) })).outcome).toBe('accepted')
    await links.synchronize()
    const iterator = a.signals.subscribe({ topics: ['typing'] })[Symbol.asyncIterator](), received = iterator.next()
    await b.signals.send('typing', { active: true }); expect((await received).value?.topic).toBe('typing'); await iterator.return?.()
    expect(f.traffic).toEqual([])
    await expect(host.application()).rejects.toThrow('HOST_UNAVAILABLE')
    await host.close()
    expect(a.status.phase).toBe('ready')
    expect((await (await a.command('say', 'still writing', { operationId: 'after-host' })).applied()).outcome).toBe('accepted')
  })

  it('returns the adopted ancestor notice across incomplete selections and durably refuses stale control replies', async () => {
    const f = await fixture(), a = await f.open(0), b = await f.open(1)
    const old = await f.registry.read(), host = b.connectControlParticipant({ exchange: f.exchange })
    const link = await connectApplications(a, b)
    await (await a.command('say', 'inherited', { operationId: 'inherited' })).applied()
    const inherited = await b.readView()
    expect(inherited.readEvents().events.map(event => event.operationId)).toEqual(['inherited'])
    inherited.release(); await link.synchronize(); await link.close()
    const ancestor = await b.recoveryPoint()
    await (await a.command('say', 'tail', { operationId: 'tail' })).applied()
    const identity = f.devices[0]!.identity
    await f.registry.select(await signTransitionRequest({ applicationId: a.applicationId, profile: 'peer-generation-v1', policy: 'eligible-members-v1',
      expectedGeneration: a.revision!.generation, coordinator: a.deviceId, requester: a.deviceId, controlRevision: 0,
      transitionId: 'second', reason: 'takeover', base: ancestor }, identity))
    await a.adopt(await f.registry.read())
    await (await a.command('say', 'unavailable', { operationId: 'unavailable' })).applied()
    await f.registry.select(await signTransitionRequest({ applicationId: a.applicationId, profile: 'peer-generation-v1', policy: 'eligible-members-v1',
      expectedGeneration: a.revision!.generation, coordinator: a.deviceId, requester: a.deviceId, controlRevision: 0,
      transitionId: 'third', reason: 'takeover', base: await a.recoveryPoint() }, identity))
    await host.application(); await expect(b.readView()).rejects.toThrow('PEER_RECOVERING')
    const notice = await b.recovery.takeover(host, { transitionId: 'recover' })
    expect(notice).toMatchObject({ previousGeneration: old.generations[0]!.id, generation: b.revision!.generation })
    expect(b.status.role).toBe('coordinator')
    const rejoin = await connectApplications(a, b); cleanup.push(() => rejoin.close())
    expect((await a.operations.get('tail'))?.status).toBe('abandoned')
    f.faults.staleAuthority = old
    await expect(host.application()).rejects.toThrow('PEER_AUTHORITY_REGRESSION')
    expect(b.status.role).toBe('coordinator')
    expect(f.traffic.every(request => request.facet === 'control')).toBe(true)
  })

  it('correlates recovery replies with the entire saved signed request across custom control transports', async () => {
    const f = await fixture(), b = await f.open(1), view = await b.readView(), before = view.revision
    view.release()
    const host = { application: () => f.registry.read(), async selectGeneration(request: SignedTransitionRequest) {
      const other = f.devices[0]!.identity
      return f.registry.select(await signTransitionRequest({ ...request.payload, requester: other.publicKey }, other))
    } }
    await expect(b.recovery.takeover(host, { transitionId: 'same-human-id' })).rejects.toThrow('APPLICATION_TRANSITION_REPLY_MISMATCH')
    expect(b.revision).toEqual(before)
    expect(await b.recovery.inspect()).toMatchObject([{ selected: null, request: { payload: { requester: b.deviceId, transitionId: 'same-human-id' } } }])
  })

  it('verifies definitions and persists exact code intent and monotonic selected publications across reopen', async () => {
    const f = await fixture(), a = await f.open(0), host = a.connectControlParticipant({ exchange: f.exchange })
    expect((await host.definition()).definition).toEqual(describeApplication(definition))
    const bytes = new TextEncoder().encode('export const version = 1;'), hash = await bytesDigest(bytes)
    const input = { operationId: 'release-one', entry: 'page.mjs', files: [{ path: 'page.mjs', hash, size: bytes.length, type: 'text/javascript' }] }
    const first = await host.preparePublication(input)
    expect(await host.publicationOperation('missing')).toBeNull()
    expect(await host.publicationOperation(input.operationId)).toEqual({ publication: first, receipt: null })
    f.faults.losePublication = true
    await expect(host.publish(first, [])).rejects.toMatchObject({
      name: 'ApplicationPublicationError', code: 'APPLICATION_PUBLICATION_OUTCOME_UNKNOWN', outcome: 'unknown',
      phase: 'submission', operationId: input.operationId, publicationId: first.id, receipt: null,
      cause: new Error('LOST_PUBLICATION_REPLY'),
    })
    expect(await host.publicationOperation(input.operationId)).toEqual({ publication: first, receipt: null })
    expect(await host.preparePublication(input)).toEqual(first)
    await host.publish(first, [])
    const second = await host.preparePublication({ ...input, operationId: 'release-two' })
    await host.publish(second, [])
    expect((await host.publish(first, [])).publication).toEqual(first)
    expect((await host.publication())?.publication).toEqual(second)
    await expect(host.preparePublication({ ...input, entry: 'different.mjs' })).rejects.toThrow('PEER_PUBLICATION_OPERATION_REUSED')
    await a.close()
    const reopened = await f.open(0, true), resumed = reopened.connectControlParticipant({ exchange: f.exchange })
    expect(await resumed.preparePublication(input)).toEqual(first)
    f.traffic.length = 0
    expect(await resumed.publicationOperation(input.operationId)).toEqual({ publication: first, receipt: { publication: first, version: 1 } })
    expect(f.traffic).toEqual([])
    f.faults.stalePublication = first
    await expect(resumed.publication()).rejects.toThrow('APPLICATION_PUBLICATION_REGRESSION')
    expect(reopened.revision).toBeNull()
    expect(reopened.status.database).toBe('idle')
    expect(f.storageOpens).toEqual([0, 0])
  })

  it('retains an acknowledged receipt when selected-head verification fails and a later retry is offline', async () => {
    const f = await fixture(), a = await f.open(0)
    const verificationFailure = new Error('POST_PUBLICATION_READ_UNAVAILABLE')
    let published = false
    const host = a.connectControlParticipant({ async exchange(request) {
      if (published && request.facet === 'control' && request.action === 'read') throw verificationFailure
      const response = await f.exchange(request)
      if (request.facet === 'publication' && request.action === 'publish') published = true
      return response
    } })
    const bytes = new TextEncoder().encode('<main>receipt</main>')
    const input = { operationId: 'committed', entry: 'index.html',
      files: [{ path: 'index.html', hash: await bytesDigest(bytes), size: bytes.length, type: 'text/html' }] }
    const publication = await host.preparePublication(input), receipt = { publication, version: 1 }
    const failed = await host.publish(publication, []).catch((error: unknown) => error)
    expect(failed).toBeInstanceOf(ApplicationPublicationError)
    expect(failed).toMatchObject({ code: 'APPLICATION_PUBLICATION_COMMITTED', outcome: 'committed', phase: 'selection',
      operationId: input.operationId, publicationId: publication.id, receipt, cause: verificationFailure })
    expect((failed as ApplicationPublicationError).cause).toBe(verificationFailure)
    await a.close()
    const reopened = await f.open(0, true), resumed = reopened.connectControlParticipant({ exchange: f.exchange })
    f.faults.offline = true; f.traffic.length = 0
    expect(await resumed.publicationOperation(input.operationId)).toEqual({ publication, receipt })
    expect(f.traffic).toEqual([])
    await expect(resumed.publish(publication, [])).rejects.toMatchObject({ outcome: 'committed', phase: 'submission', receipt,
      cause: new Error('HOST_UNAVAILABLE') })
    f.faults.offline = false
    expect(await resumed.preparePublication(input)).toEqual(publication)
    expect(await resumed.publish(publication, [])).toEqual(receipt)
    expect(await f.publications.read()).toEqual([publication])
    expect(f.storageOpens).toEqual([0, 0])
  })

  it('drains a validated receipt write across session closure and recovers it after reopen', async () => {
    const f = await fixture(), a = await f.open(0), host = a.connectControlParticipant({ exchange: f.exchange })
    const bytes = new TextEncoder().encode('<main>closing</main>')
    const publication = await host.preparePublication({ operationId: 'closing-receipt', entry: 'index.html',
      files: [{ path: 'index.html', hash: await bytesDigest(bytes), size: bytes.length, type: 'text/html' }] })
    const receipt = { publication, version: 1 }, store = f.devices[0]!.store, put = store.put.bind(store)
    let entered!: () => void, release!: () => void
    const writing = new Promise<void>(resolve => { entered = resolve }), gate = new Promise<void>(resolve => { release = resolve })
    vi.spyOn(store, 'put').mockImplementation(async (key, value) => {
      if (key.startsWith('peer-session/publication-receipt/')) { entered(); await gate }
      await put(key, value)
    })
    const pending = host.publish(publication, [])
    const rejected = expect(pending).rejects.toMatchObject({ outcome: 'committed', phase: 'selection', receipt,
      cause: new Error('APPLICATION_SESSION_CLOSED') })
    await writing
    let closed = false
    const closing = a.close().then(() => { closed = true })
    try {
      await Promise.resolve(); expect(closed).toBe(false)
    } finally { release(); await Promise.all([closing, rejected]) }
    const reopened = await f.open(0, true), resumed = reopened.connectControlParticipant({ exchange: f.exchange })
    expect(await resumed.publicationOperation('closing-receipt')).toEqual({ publication, receipt })
    expect(await f.publications.read()).toEqual([publication])
  })

  it('keeps a delayed acknowledgement unknown after timeout and retries the original operation on reopen', async () => {
    const f = await fixture(), a = await f.open(0)
    let entered!: () => void, release!: () => void
    const submitted = new Promise<void>(resolve => { entered = resolve }), gate = new Promise<void>(resolve => { release = resolve })
    const host = a.connectControlParticipant({ timeoutMs: 1_000, async exchange(request) {
      const response = await f.exchange(request)
      if (request.facet === 'publication' && request.action === 'publish') { entered(); await gate }
      return response
    } })
    const bytes = new TextEncoder().encode('<main>late</main>')
    const input = { operationId: 'delayed', entry: 'index.html',
      files: [{ path: 'index.html', hash: await bytesDigest(bytes), size: bytes.length, type: 'text/html' }] }
    const publication = await host.preparePublication(input)
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] })
    try {
      const pending = host.publish(publication, [])
      const rejected = expect(pending).rejects.toMatchObject({ outcome: 'unknown', phase: 'submission', receipt: null,
        operationId: input.operationId, publicationId: publication.id, cause: new Error('APPLICATION_CONTROL_TIMEOUT') })
      await submitted; await vi.advanceTimersByTimeAsync(1_000); await rejected
      release()
    } finally { release(); vi.useRealTimers() }
    expect(await host.publicationOperation(input.operationId)).toEqual({ publication, receipt: null })
    await a.close()
    const reopened = await f.open(0, true), resumed = reopened.connectControlParticipant({ exchange: f.exchange })
    expect(await resumed.preparePublication(input)).toEqual(publication)
    expect(await resumed.publish(publication, [])).toEqual({ publication, version: 1 })
    expect(await f.publications.read()).toEqual([publication])
  })

  it.each(['missing', 'invalid-version', 'mismatched-publication'] as const)('does not retain a receipt with %s as committed', async fault => {
    const f = await fixture(), a = await f.open(0)
    const host = a.connectControlParticipant({ async exchange(request) {
      const response = await f.exchange(request)
      if (request.facet !== 'publication' || request.action !== 'publish') return response
      const publication = (request.payload as { publication: SignedPublication }).publication
      const result = fault === 'missing' ? null : fault === 'invalid-version' ? { publication, version: 0 }
        : { publication: { ...publication, signature: '00'.repeat(64) }, version: 1 }
      return createParticipantResponse(request, result)
    } })
    const bytes = new TextEncoder().encode('<main>untrusted</main>')
    const publication = await host.preparePublication({ operationId: 'invalid-reply', entry: 'index.html',
      files: [{ path: 'index.html', hash: await bytesDigest(bytes), size: bytes.length, type: 'text/html' }] })
    await expect(host.publish(publication, [])).rejects.toMatchObject({ outcome: 'unknown', phase: 'receipt', receipt: null,
      cause: new Error('APPLICATION_PUBLICATION_REPLY_MISMATCH') })
    expect(await host.publicationOperation('invalid-reply')).toEqual({ publication, receipt: null })
  })

  it('keeps canonical verification errors after a confirmed commit as failures', async () => {
    const f = await fixture(), a = await f.open(0), host = a.connectControlParticipant({ exchange: f.exchange })
    const bytes = new TextEncoder().encode('<main>verification</main>')
    const files = [{ path: 'index.html', hash: await bytesDigest(bytes), size: bytes.length, type: 'text/html' }]
    const first = await host.preparePublication({ operationId: 'verified-one', entry: 'index.html', files })
    await host.publish(first, [])
    const second = await host.preparePublication({ operationId: 'verified-two', entry: 'index.html', files })
    f.faults.stalePublication = { ...first, signature: '00'.repeat(64) }
    await expect(host.publish(second, [])).rejects.toMatchObject({ outcome: 'committed', phase: 'selection',
      receipt: { publication: second, version: 2 }, cause: { message: 'PEER_SIGNATURE_INVALID', code: 'PEER_SIGNATURE_INVALID' } })
    f.traffic.length = 0
    await expect(host.publish({ ...second, signature: '00'.repeat(64) }, [])).rejects.toThrow('PEER_SIGNATURE_INVALID')
    expect(f.traffic).toEqual([])
    expect(await host.publicationOperation('verified-two')).toEqual({ publication: second, receipt: { publication: second, version: 2 } })
  })

  it('verifies every skipped publication before remembering the new selected head', async () => {
    const f = await fixture(), a = await f.open(0), b = await f.open(1)
    const publisher = a.connectControlParticipant({ exchange: f.exchange }), reader = b.connectControlParticipant({ exchange: f.exchange })
    const bytes = new TextEncoder().encode('<main>page</main>'), hash = await bytesDigest(bytes)
    const files = [{ path: 'index.html', hash, size: bytes.length, type: 'text/html' }]
    const first = await publisher.preparePublication({ operationId: 'one', entry: 'index.html', files }); await publisher.publish(first, [])
    await reader.publication()
    for (const operationId of ['two', 'three']) await publisher.publish(await publisher.preparePublication({ operationId, entry: 'index.html', files }), [])
    f.traffic.length = 0
    expect((await reader.publication())?.publication.payload.revision).toBe(2)
    expect(f.traffic.filter(request => request.facet === 'publication' && request.action === 'read')).toHaveLength(3)
  })

  it('fences unanswered control work when the owning session closes', async () => {
    const f = await fixture(), a = await f.open(0)
    let entered!: () => void
    const started = new Promise<void>(resolve => { entered = resolve })
    const host = a.connectControlParticipant({ exchange() { entered(); return new Promise(() => {}) } })
    const pending = host.application(), checked = expect(pending).rejects.toThrow('APPLICATION_SESSION_CLOSED')
    await started; await a.close(); await checked
    expect(host.signal.aborted).toBe(true)
    await expect(host.application()).rejects.toThrow('APPLICATION_SESSION_CLOSED')
  })
})
