import { generateEd25519KeyPair, bytesToHex } from '@chronolog/protocol'
import type { CapabilitySnapshot } from '@chronolog/capabilities'
import type { FeedLink } from '@chronolog/records'
import { SignalChannel } from '@chronolog/signals'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { createGovernedPeerService } from '@chronolog/agent-service/governed-peer'
import { openAuthenticatedPeerLink } from '@chronolog/agent-service/peer-link'

vi.mock('@chronolog/agent-service/peer-link', () => ({ openAuthenticatedPeerLink: vi.fn() }))
beforeEach(() => vi.resetAllMocks())
afterEach(() => vi.restoreAllMocks())

async function fixture() {
  const identity = await generateEd25519KeyPair(), groupId = new Uint8Array(32).fill(1), grantId = new Uint8Array(32).fill(2)
  const snapshot: CapabilitySnapshot = { encryptionEpoch: 0n, groupId, revision: 0n, revisionDigest: new Uint8Array(32), rootAdminPublicKey: new Uint8Array(32),
    capabilityLogFeed: new Uint8Array(32), policies: new Map(), validatorFloorMs: 0n,
    capabilities: new Map([[bytesToHex(grantId), { id: grantId, grantedAtRevision: 0n,
      grant: { role: 'reader', transportAuthor: 'local', subjectId: identity.publicKeyBytes, signingPublicKey: identity.publicKeyBytes,
        validFromRevision: 0n, hpkePublicKey: new Uint8Array(32) } }]]) }
  const detach = vi.fn(), close = vi.fn(async () => {}), rawClose = vi.fn(async () => {})
  const connection = { signal: new AbortController().signal, send: async () => {}, async *frames() {}, close: rawClose,
    live: { send: async () => {}, async *frames() {}, close: rawClose } }
  const local: FeedLink = { identity: 'local', read: async () => [], readEvidence: async () => [], readPayload: async () => null, async *watch() {} }
  const session = { link: { ...local, identity: 'remote' }, peer: { authorId: identity.publicKeyBytes, grantId, feedId: 'remote' },
    completion: new Promise<void>(() => {}), sendSignal: async () => {}, close }
  const attach = vi.fn(() => detach)
  vi.mocked(openAuthenticatedPeerLink).mockResolvedValue(session)
  return { identity, groupId, activeMembership: () => snapshot, local, attach, connection, session, detach, close, rawClose }
}

describe('browser composition uses the shared governed connection owner', () => {
  it('releases the authenticated session without retaining replication when signal attachment fails', async () => {
    const f = await fixture(), owner = await createGovernedPeerService(f)
    vi.spyOn(SignalChannel.prototype, 'attachRoute').mockImplementation(() => { throw new Error('SIGNAL_ROUTE_QUOTA_EXCEEDED') })
    try {
      await expect(owner.connectPeer({ connection: f.connection })).rejects.toThrow('SIGNAL_ROUTE_QUOTA_EXCEEDED')
      expect(f.attach).not.toHaveBeenCalled()
      expect(f.close).toHaveBeenCalledTimes(1)
    } finally { await owner.close() }
  })

  it('closes an opening connection and refuses late attachment after owner shutdown', async () => {
    const f = await fixture()
    let release!: (session: typeof f.session) => void
    vi.mocked(openAuthenticatedPeerLink).mockImplementation(() => new Promise(resolve => { release = resolve }))
    const owner = await createGovernedPeerService(f), pending = owner.connectPeer({ connection: f.connection })
    await owner.close()
    expect(f.rawClose).toHaveBeenCalledTimes(1)
    release(f.session)
    await expect(pending).rejects.toThrow('PEER_SERVICE_CLOSED')
    expect(f.attach).not.toHaveBeenCalled()
    expect(f.close).toHaveBeenCalledTimes(1)
  })
})
