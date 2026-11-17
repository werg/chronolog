import { generateEd25519KeyPair, bytesToHex } from '@chronolog/protocol'
import type { CapabilitySnapshot } from '@chronolog/capabilities'
import type { PortableFeedTransport } from '@chronolog/records'
import { SignalChannel } from '@chronolog/signals'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { openAuthenticatedPeerLink } from '@chronolog/agent-service/peer-link'
import { browserPeerConnections } from './peer-connections.js'

vi.mock('@chronolog/agent-service/peer-link', () => ({ openAuthenticatedPeerLink: vi.fn() }))
beforeEach(() => vi.resetAllMocks())

async function fixture() {
  const identity = await generateEd25519KeyPair(), groupId = new Uint8Array(32).fill(1), grantId = new Uint8Array(32).fill(2)
  const snapshot: CapabilitySnapshot = { groupId, revision: 0n, revisionDigest: new Uint8Array(32), rootAdminPublicKey: new Uint8Array(32),
    capabilityLogFeed: new Uint8Array(32), policies: new Map(), validatorFloorMs: 0n,
    capabilities: new Map([[bytesToHex(grantId), { id: grantId, grantedAtRevision: 0n,
      grant: { role: 'reader', subjectId: identity.publicKeyBytes, signingPublicKey: identity.publicKeyBytes, validFromRevision: 0n, hpkePublicKey: new Uint8Array(32) } }]]) }
  const detach = vi.fn(), close = vi.fn(async () => {}), rawClose = vi.fn(async () => {})
  const connection = { send: async () => {}, async *frames() {}, close: rawClose }
  const session = { link: { identity: 'remote', read: async () => [], readEvidence: async () => [], readPayload: async () => null, async *watch() {} },
    peer: { authorId: identity.publicKeyBytes, grantId, feedId: 'remote' },
    completion: new Promise<void>(() => {}), sendSignal: async () => {}, close }
  const connect = vi.fn(() => detach)
  const transport = { asLink: () => ({ identity: 'local' }), connect } as unknown as PortableFeedTransport
  vi.mocked(openAuthenticatedPeerLink).mockResolvedValue(session)
  return { identity, groupId, current: () => snapshot, connection, session, transport, connect, detach, close, rawClose }
}

describe('browser peer connection ownership', () => {
  it('releases authenticated sessions and replication attachment when signal attachment fails', async () => {
    const f = await fixture()
    const signals = new SignalChannel({ scope: 'room', identity: f.identity, authorize: () => true, maxRoutes: 1, send: async () => {} })
    const owner = browserPeerConnections({ ...f, signals })
    await expect(owner.connectPeer({ connection: f.connection })).rejects.toThrow('SIGNAL_ROUTE_QUOTA_EXCEEDED')
    expect(f.detach).toHaveBeenCalledTimes(1)
    expect(f.close).toHaveBeenCalledTimes(1)
    expect(f.rawClose).toHaveBeenCalledTimes(1)
    signals.close(); await owner.close()
  })

  it('closes an opening connection and refuses late attachment after owner shutdown', async () => {
    const f = await fixture()
    let release!: (session: typeof f.session) => void
    vi.mocked(openAuthenticatedPeerLink).mockImplementation(() => new Promise(resolve => { release = resolve }))
    const owner = browserPeerConnections(f), pending = owner.connectPeer({ connection: f.connection })
    await owner.close()
    expect(f.rawClose).toHaveBeenCalledTimes(1)
    release(f.session)
    await expect(pending).rejects.toThrow('PEER_CLOSED')
    expect(f.connect).not.toHaveBeenCalled()
    expect(f.close).toHaveBeenCalledTimes(1)
  })
})
