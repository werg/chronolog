import { generateEd25519KeyPair, bytesToHex } from '@chronolog/protocol'
import { describe, expect, it } from 'vitest'
import { createCapabilitySignals } from './signals.js'
import type { CapabilitySnapshot, EffectiveCapability } from './types.js'

describe('group signal authorization adapter', () => {
  it('lets a reader subscribe without write rights and a signal-only author send without transactions', async () => {
    const writer = await generateEd25519KeyPair(), reader = await generateEd25519KeyPair()
    const groupId = new Uint8Array(32).fill(1), grantId = new Uint8Array(32).fill(2)
    const grant: EffectiveCapability = { id: grantId, grantedAtRevision: 0n,
      grant: { role: 'writer', subjectId: writer.publicKeyBytes, signingPublicKey: writer.publicKeyBytes, validFromRevision: 0n,
        program: { sql: false, topics: [], signals: ['presence'] } } }
    let snapshot: CapabilitySnapshot = { groupId, revision: 0n, revisionDigest: new Uint8Array(32), rootAdminPublicKey: new Uint8Array(32),
      capabilityLogFeed: new Uint8Array(32), capabilities: new Map([[bytesToHex(grantId), grant]]), policies: new Map(), validatorFloorMs: 0n }
    const outgoing: Uint8Array[] = []
    const sender = createCapabilitySignals({ groupId, identity: writer, current: () => snapshot, send: async frame => { outgoing.push(frame) } })
    const receiver = createCapabilitySignals({ groupId, identity: reader, current: () => snapshot, send: async () => {} })
    const iterator = receiver.subscribe({ topics: ['presence'] })[Symbol.asyncIterator](), pending = iterator.next()
    const sent = await sender.send('presence', { online: true })
    await receiver.receive(outgoing[0]!)
    expect((await pending).value).toEqual(sent)
    await expect(receiver.send('presence', { online: true })).rejects.toThrow('SIGNAL_UNAUTHORIZED')
    await expect(sender.send('admin', true)).rejects.toThrow('SIGNAL_UNAUTHORIZED')
    await sender.send('presence', { online: false })
    snapshot = { ...snapshot, revision: 1n, capabilities: new Map([[bytesToHex(grantId), { ...grant, revokedAtRevision: 1n }]]) }
    await expect(receiver.receive(outgoing[1]!)).rejects.toThrow('SIGNAL_UNAUTHORIZED')
    await expect(sender.send('presence', null)).rejects.toThrow('SIGNAL_UNAUTHORIZED')
    await iterator.return?.(); sender.close(); receiver.close()
  })
})
