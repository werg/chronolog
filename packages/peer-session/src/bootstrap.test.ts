import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, describe, expect, it } from 'vitest'
import {
  applicationDescriptionDigest, controlParticipantGrant, createGenerationRegistry, createPeerIdentity, MemoryPeerStore, participantGrant,
  peerDigest, signApplicationDescriptor, signControlRevision, type GenerationRegistry, type SignedTransitionRequest,
} from '@chronolog/peer-generation'
import { emit, program } from '@chronolog/protocol'
import { openApplicationSession, type ApplicationBootstrapHost, type ApplicationConfiguration, type ApplicationPublication } from './bootstrap.js'
import { defineApplication, defineCommand, defineQuery } from './definition.js'
import { openNativeDevice } from './native.js'
import { connectApplications, type ApplicationReadView } from './session.js'
import { connectApplicationWorkerHost, serveApplicationWorkerHost } from './worker-host.js'

const cleanup: Array<() => void | Promise<void>> = []
afterEach(async () => { for (const close of cleanup.splice(0).reverse()) await close() })
const definition = defineApplication({ id: 'bootstrap-messages', version: '1', commands: {
  measure: defineCommand({ description: 'Record a fractional value', input: { type: 'number', minimum: 0.1, maximum: 0.9 }, prepare: value => program(emit('measurement', { value })) }),
  say: defineCommand({ description: 'Post a message', input: { type: 'string' }, prepare: text => program(emit('message', { text })) }),
}, queries: {
  messages: defineQuery({ description: 'Read messages', input: { type: 'null' }, read: (view: ApplicationReadView) => view.readEvents() }),
} })
const applicationId = 'a7'.repeat(32)

async function fixture() {
  const directory = await mkdtemp(join(tmpdir(), 'peer-bootstrap-'))
  cleanup.push(() => rm(directory, { recursive: true, force: true }))
  const a = await openNativeDevice({ path: join(directory, 'a.sqlite'), create: true }), b = await openNativeDevice({ path: join(directory, 'b.sqlite'), create: true })
  cleanup.push(() => a.close(), () => b.close())
  const signer = await createPeerIdentity(), store = new MemoryPeerStore()
  let registry: GenerationRegistry | undefined, publication: ApplicationPublication | undefined, fingerprint: string | undefined
  let configureLost = false, selectionLost = false, requests = 0
  const configurations: ApplicationConfiguration[] = [], selections: SignedTransitionRequest[] = []
  const host: ApplicationBootstrapHost = {
    async configureApplication(configuration) {
      requests++; configurations.push(structuredClone(configuration))
      const digest = await peerDigest({ ...configuration, definition: await applicationDescriptionDigest(configuration.definition) })
      if (fingerprint !== undefined && fingerprint !== digest) throw new Error('peer_application_immutable')
      if (registry === undefined) {
        const descriptor = await signApplicationDescriptor({ applicationId, historyId: configuration.historyId,
          profile: 'peer-generation-v1', policy: 'eligible-members-v1', controlPublicKey: signer.publicKey,
          executionManifestDigest: configuration.executionManifestDigest, definitionDigest: await applicationDescriptionDigest(configuration.definition),
          schemaAdministrator: configuration.schemaAdministrator, schemaDigest: configuration.schema === null ? null : await peerDigest(configuration.schema) }, signer)
        const control = await signControlRevision({ applicationId, profile: 'peer-generation-v1', policy: 'eligible-members-v1',
          revision: 0, previous: null, epoch: configuration.epoch, keyDigest: configuration.keyDigest, recoveryFloor: null,
          grants: [controlParticipantGrant(signer.publicKey), ...configuration.members.map(member => 'grant' in member ? member.grant : participantGrant(member.publicKey, {
            ...(member.administrator === undefined ? {} : { administrator: member.administrator }),
            ...(member.dataRole === undefined ? {} : { dataRole: member.dataRole }),
          }))] }, signer)
        registry = await createGenerationRegistry({ store, descriptor, controls: [control], signer })
        publication = { descriptor, definition: configuration.definition, schema: configuration.schema }; fingerprint = digest
      }
      if (configureLost) { configureLost = false; throw new Error('CONFIGURATION_REPLY_LOST') }
      return registry.read()
    },
    async application() { requests++; if (registry === undefined) throw new Error('APPLICATION_NOT_FOUND'); return registry.read() },
    async definition() { requests++; if (publication === undefined) throw new Error('APPLICATION_NOT_FOUND'); return publication },
    async selectGeneration(request) {
      requests++; selections.push(structuredClone(request))
      if (registry === undefined) throw new Error('APPLICATION_NOT_FOUND')
      const value = await registry.select(request)
      if (selectionLost) { selectionLost = false; throw new Error('SELECTION_REPLY_LOST') }
      return value
    },
  }
  return { a, b, directory, host, configurations, selections, get requests() { return requests },
    loseConfiguration() { configureLost = true }, loseSelection() { selectionLost = true } }
}

describe('public application startup', () => {
  it('bootstraps through the page host bridge, preserves fractional schemas and exact retries, enrolls a reader and resumes offline', async () => {
    const f = await fixture(), members = [{ publicKey: f.a.identity.publicKey }, { publicKey: f.b.identity.publicKey }]
    const endpoint = new MessageChannel(), server = serveApplicationWorkerHost(endpoint.port1, f.host)
    const host = await connectApplicationWorkerHost(endpoint.port2)
    cleanup.push(async () => { await host.close(); server.close(); endpoint.port1.close(); endpoint.port2.close() })
    const initial = { definition, applicationId, host, create: { members } }
    f.loseConfiguration()
    await expect(openApplicationSession({ ...initial, device: f.a })).rejects.toThrow('CONFIGURATION_REPLY_LOST')
    const second = await openNativeDevice({ path: join(f.directory, 'a.sqlite') })
    f.loseSelection()
    await expect(openApplicationSession({ ...initial, device: second })).rejects.toThrow('SELECTION_REPLY_LOST')
    const third = await openNativeDevice({ path: join(f.directory, 'a.sqlite') })
    const a = await openApplicationSession({ ...initial, device: third })
    cleanup.push(() => a.close())
    expect(f.configurations).toHaveLength(3)
    expect(f.configurations[1]).toEqual(f.configurations[0]); expect(f.configurations[2]).toEqual(f.configurations[0])
    expect(f.selections).toHaveLength(2); expect(f.selections[1]).toEqual(f.selections[0])
    expect((await f.host.application()).generations).toHaveLength(1)
    expect(a.deviceId).toBe(f.a.identity.publicKey)
    const body = f.configurations[0]!
    expect(Object.keys(body)).not.toContain('definitionDigest'); expect(Object.keys(body)).not.toContain('schemaDigest')
    expect(body.definition.commands.find(command => command.name === 'measure')?.input).toMatchObject({ minimum: 0.1, maximum: 0.9 })
    const firstKey = a.keys.epochKeys.get(0)!
    expect(JSON.stringify(body)).not.toContain(Array.from(firstKey, byte => byte.toString(16).padStart(2, '0')).join(''))
    const b = await openApplicationSession({ device: f.b, definition, applicationId, host })
    cleanup.push(() => b.close())
    expect(b.status.phase).toBe('awaiting-keys')
    const link = await connectApplications(a, b)
    cleanup.push(() => link.close())
    await (await b.command('say', 'public startup', { operationId: 'once' })).applied({ signal: AbortSignal.timeout(5000) })
    await link.synchronize()
    await expect(openApplicationSession({ ...initial, device: third })).rejects.toThrow('APPLICATION_DEVICE_IN_USE')
    expect((await a.query('messages', null)).value.events).toHaveLength(1)
    const identity = b.deviceId, requests = f.requests
    await b.close()
    const reopened = await openApplicationSession({ device: await openNativeDevice({ path: join(f.directory, 'b.sqlite') }), definition, applicationId })
    cleanup.push(() => reopened.close())
    expect(f.requests).toBe(requests)
    expect(reopened.deviceId).toBe(identity)
    expect(reopened.keys.missing()).toEqual([])
    expect((await reopened.query('messages', null)).value.events).toHaveLength(1)
    expect(await reopened.operations.get('once')).toMatchObject({ status: 'applied', outcome: 'accepted' })
  })

  it('rejects changed creation inputs and unbound join metadata without replacing identity', async () => {
    const f = await fixture(), a = await openApplicationSession({ device: f.a, definition, applicationId, host: f.host, create: {} })
    await a.close()
    await expect(openApplicationSession({ device: await openNativeDevice({ path: join(f.directory, 'a.sqlite') }), definition, applicationId,
      host: f.host, create: { historyId: 'replace-the-history' } })).rejects.toThrow('APPLICATION_CREATION_INPUT_CHANGED')
    const malicious = { ...f.host, async definition() { const value = await f.host.definition(); return { ...value, definition: { ...value.definition, version: '2' } } } }
    await expect(openApplicationSession({ device: f.b, definition, applicationId, host: malicious })).rejects.toThrow('APPLICATION_DEFINITION_MISMATCH')
    const device = await openNativeDevice({ path: join(f.directory, 'b.sqlite') })
    expect(device.identity.publicKey).toBe(f.b.identity.publicKey)
    await device.close()
  })
})
