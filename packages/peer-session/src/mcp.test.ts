import { afterEach, describe, expect, it } from 'vitest'
import { createEventMaterializationRuntime, eventExecutionManifest } from '@chronolog/materializer'
import {
  bytesDigest, createGenerationRegistry, createPeerIdentity, MemoryPeerStore, participantGrant,
  signApplicationDescriptor, signControlRevision, signTransitionRequest,
} from '@chronolog/peer-generation'
import { bytesToHex, emit, executionManifestArtifacts, program } from '@chronolog/protocol'
import { applicationDefinitionDigest, defineApplication, defineCommand, defineQuery } from './definition.js'
import { openApplicationDevice } from './device.js'
import { openPeerApplication } from './runtime.js'
import type { ApplicationReadView } from './session.js'
import { createApplicationMcpServer, serveApplicationMcpLines } from './mcp.js'

const cleanup: Array<() => void | Promise<void>> = []
afterEach(async () => { for (const close of cleanup.splice(0).reverse()) await close() })
const definition = defineApplication({ id: 'local-tools', version: '1', commands: {
  say: defineCommand({ description: 'Say something', input: { type: 'string', minLength: 1 }, prepare: text => program(emit('message', text)) }),
}, queries: { messages: defineQuery({ description: 'Read messages', input: { type: 'null' }, read: (view: ApplicationReadView) => view.readEvents() }) } })
async function fixture() {
  const host = await createPeerIdentity(), device = await openApplicationDevice({ store: new MemoryPeerStore(), create: true })
  const key = crypto.getRandomValues(new Uint8Array(32)), manifest = await executionManifestArtifacts(await eventExecutionManifest('peer-generation-v1'))
  const descriptor = await signApplicationDescriptor({ applicationId: '49'.repeat(32), historyId: 'local-mcp', profile: 'peer-generation-v1',
    policy: 'eligible-members-v1', controlPublicKey: host.publicKey, schemaAdministrator: device.identity.publicKey, schemaDigest: null,
    definitionDigest: await applicationDefinitionDigest(definition), executionManifestDigest: bytesToHex(manifest.executionManifestDigest) }, host)
  const control = await signControlRevision({ applicationId: descriptor.payload.applicationId, profile: descriptor.payload.profile,
    policy: descriptor.payload.policy, revision: 0, previous: null, epoch: 0, keyDigest: await bytesDigest(key), recoveryFloor: null,
    grants: [participantGrant(device.identity.publicKey, { administrator: true })] }, host)
  const registry = await createGenerationRegistry({ store: new MemoryPeerStore(), descriptor, signer: host, controls: [control] })
  await registry.select(await signTransitionRequest({ applicationId: descriptor.payload.applicationId, profile: descriptor.payload.profile,
    policy: descriptor.payload.policy, transitionId: 'initial', expectedGeneration: null, coordinator: device.identity.publicKey,
    requester: device.identity.publicKey, controlRevision: 0, reason: 'create', base: null }, device.identity))
  const session = await openPeerApplication({ device, definition, authority: await registry.read(), epochKeys: new Map([[0, key]]),
    createMaterializer: () => createEventMaterializationRuntime({ store: device.store, namespace: 'mcp', historyProfile: 'peer-generation-v1' }) })
  cleanup.push(() => session.close())
  return session
}

describe('local application MCP', () => {
  it('negotiates tools from the definition and preserves exact command identity after a lost reply', async () => {
    const session = await fixture(), server = createApplicationMcpServer(session)
    cleanup.push(() => server.close())
    const request = (id: number, method: string, params = {}) => server.handle({ jsonrpc: '2.0', id, method, params })
    expect(await request(0, 'tools/list')).toMatchObject({ error: { code: -32000 } })
    expect(await request(1, 'initialize', { protocolVersion: '2025-06-18' })).toMatchObject({ result: { protocolVersion: '2025-06-18', capabilities: { tools: {} } } })
    expect(await request(2, 'tools/list')).toMatchObject({ result: { tools: expect.arrayContaining([expect.objectContaining({ name: 'changes' }), expect.objectContaining({ name: 'command' })]) } })
    const command = { name: 'command', arguments: { name: 'say', input: 'once', operationId: 'intent-1' } }
    await request(3, 'tools/call', command) // The caller deliberately loses this reply.
    const retry = await request(4, 'tools/call', command)
    expect(retry).toMatchObject({ result: { content: [{ type: 'text', text: expect.stringContaining('"status":"applied"') }] } })
    expect((await session.query('messages', null)).value.events).toHaveLength(1)
  })

  it('cancels only a pending change wait and serves standard newline-delimited JSON-RPC', async () => {
    const session = await fixture(), server = createApplicationMcpServer(session)
    cleanup.push(() => server.close())
    await server.handle({ jsonrpc: '2.0', id: 'init', method: 'initialize' })
    const waiting = server.handle({ jsonrpc: '2.0', id: 'watch', method: 'tools/call', params: { name: 'changes', arguments: { after: session.revision } } })
    expect(await server.handle({ jsonrpc: '2.0', method: 'notifications/cancelled', params: { requestId: 'watch' } })).toBeUndefined()
    expect(await waiting).toMatchObject({ result: { isError: true, content: [{ text: expect.stringContaining('APPLICATION_MCP_CANCELLED') }] } })
    expect(session.status.phase).toBe('ready')
    const lines: string[] = []
    async function* input() {
      yield JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize' })
      yield JSON.stringify({ jsonrpc: '2.0', method: 'notifications/initialized' })
      yield JSON.stringify({ jsonrpc: '2.0', id: 2, method: 'tools/list' })
      yield 'invalid JSON'
    }
    await serveApplicationMcpLines(session, { input: input(), write: line => { lines.push(line) } })
    const responses = lines.map(line => JSON.parse(line) as unknown)
    expect(responses).toHaveLength(3)
    expect(responses).toContainEqual(expect.objectContaining({ id: null, error: { code: -32700, message: 'Invalid JSON-RPC input' } }))
    expect(responses).toContainEqual(expect.objectContaining({ id: 2, result: { tools: expect.any(Array) } }))
  })

  it('releases a blocked input stream when its owner cancels', async () => {
    const session = await fixture(), controller = new AbortController()
    let released = false
    const input: AsyncIterableIterator<string> = {
      [Symbol.asyncIterator]() { return this },
      next: () => new Promise<IteratorResult<string>>(() => undefined),
      return: () => { released = true; return Promise.resolve({ done: true, value: undefined }) },
    }
    const running = serveApplicationMcpLines(session, { input, signal: controller.signal, write: () => undefined })
    controller.abort(new Error('OWNER_CANCELLED'))
    await expect(running).rejects.toThrow('OWNER_CANCELLED')
    expect(released).toBe(true)
    expect(session.status.phase).toBe('ready')
  })
})
