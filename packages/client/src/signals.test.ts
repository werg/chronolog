import { createCapabilitySignals, type CapabilitySnapshot, type EffectiveCapability } from '@chronolog/capabilities'
import { bytesToBase64Url, bytesToHex, generateEd25519KeyPair } from '@chronolog/protocol'
import { ChronologRpcError, InProcessRpcTransport, NodeRpcService, type ChronologRpcNodeService, type RpcTransport } from '@chronolog/rpc'
import type { EphemeralSignal } from '@chronolog/signals'
import { describe, expect, it, vi } from 'vitest'
import { ChronologClient } from './client.js'

describe('public live signal client', () => {
  it('lets a read-only client subscribe with no SQL, transactions, finality or private Worker commands', async () => {
    const writer = await generateEd25519KeyPair(), reader = await generateEd25519KeyPair()
    const groupId = new Uint8Array(32).fill(4), writerId = new Uint8Array(32).fill(5), readerId = new Uint8Array(32).fill(6)
    const grants: EffectiveCapability[] = [
      { id: writerId, grantedAtRevision: 0n, grant: { role: 'writer', subjectId: writer.publicKeyBytes, signingPublicKey: writer.publicKeyBytes,
        validFromRevision: 0n, program: { sql: false, topics: [], signals: ['presence'] } } },
      { id: readerId, grantedAtRevision: 0n, grant: { role: 'reader', subjectId: reader.publicKeyBytes, signingPublicKey: reader.publicKeyBytes,
        validFromRevision: 0n, hpkePublicKey: new Uint8Array(32) } },
    ]
    const snapshot: CapabilitySnapshot = { groupId, revision: 0n, revisionDigest: new Uint8Array(32), rootAdminPublicKey: new Uint8Array(32),
      capabilityLogFeed: new Uint8Array(32), capabilities: new Map(grants.map(grant => [bytesToHex(grant.id), grant])), policies: new Map(), validatorFloorMs: 0n }
    const receiver = createCapabilitySignals({ groupId, identity: reader, current: () => snapshot, send: async () => {} })
    const sender = createCapabilitySignals({ groupId, identity: writer, current: () => snapshot, send: async frame => { await receiver.receive(frame) } })
    // Deliberately no authoring, SQL, operation or finality service exists here.
    const node = { groupId } as ChronologRpcNodeService
    const client = new ChronologClient({ groupId: bytesToBase64Url(groupId), transport: new InProcessRpcTransport(new NodeRpcService({ node, signals: receiver })) })
    const iterator = client.signals.subscribe({ topics: ['presence'] })[Symbol.asyncIterator]()
    const pending = iterator.next()
    // Open the transport's async iterator before delivering the live message.
    await Promise.resolve(); await Promise.resolve()
    const sent = await sender.send('presence', { online: true })
    expect((await pending).value).toEqual(sent)
    await expect(client.signals.send('presence', { online: true })).rejects.toMatchObject({ code: 'permission_denied', retryable: false })
    await expect(client.signals.send('bad topic', true)).rejects.toMatchObject({ code: 'invalid_argument', retryable: false })
    await iterator.return?.()
    const idle = client.signals.subscribe()[Symbol.asyncIterator](), reading = idle.next()
    await Promise.resolve(); await Promise.resolve()
    expect((await idle.return?.())?.done).toBe(true)
    expect((await reading).done).toBe(true)
    await client.close(); sender.close(); receiver.close()
  })

  it('never automatically retries sends or silently reconnects signal subscriptions', async () => {
    const failure = new ChronologRpcError('transport_unavailable', 'disconnected')
    const unary = vi.fn(async () => { throw failure })
    const message: EphemeralSignal = { scope: 'scope', authorId: 'a'.repeat(64), sessionId: 'b'.repeat(64), sequence: 1,
      topic: 'progress', payload: 1, issuedAtMs: 1, expiresAtMs: 2 }
    const stream = vi.fn(async function* () { yield message; throw failure })
    const client = new ChronologClient({ groupId: 'group', transport: { unary, stream } as RpcTransport, unaryRetryAttempts: 5 })
    await expect(client.signals.send('progress', 1)).rejects.toBe(failure)
    expect(unary).toHaveBeenCalledTimes(1)
    const iterator = client.signals.subscribe()[Symbol.asyncIterator]()
    expect((await iterator.next()).value).toEqual(message)
    await expect(iterator.next()).rejects.toBe(failure)
    expect(stream).toHaveBeenCalledTimes(1)
    await client.close()
  })
})
