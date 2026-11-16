import { afterEach, describe, expect, it } from 'vitest'

import { feedIdFromPublicKey, webFeedCrypto, webFeedSigner } from './feed-codec.js'
import { DurableFeedStore, type AtomicBytesStore } from './store.js'
import { connectInProcess, PortableFeedTransport } from './transport.js'
import { payloadHash } from './payload.js'

const peers: PortableFeedTransport[] = []
afterEach(async () => { await Promise.all(peers.splice(0).map((peer) => peer.close())) })

async function peer() {
  const values = new Map<string, Uint8Array>()
  const bytes: AtomicBytesStore = {
    get: async (key) => values.get(key)?.slice() ?? null,
    put: async (key, value) => { values.set(key, value.slice()) },
  }
  const keys = await crypto.subtle.generateKey('Ed25519', true, ['sign', 'verify'])
  const id = feedIdFromPublicKey(new Uint8Array(await crypto.subtle.exportKey('raw', keys.publicKey)))
  const transport = new PortableFeedTransport({ store: await DurableFeedStore.open(bytes, webFeedCrypto), signer: webFeedSigner(id, keys.privateKey), crypto: webFeedCrypto })
  peers.push(transport)
  return transport
}

describe('portable peer replication', () => {
  it('fetches and retains only explicitly requested payloads without following their author feed', async () => {
    const [author, reader, relay] = await Promise.all([peer(), peer(), peer()])
    const payload = new Uint8Array(96_000).fill(7), hash = await payloadHash(payload)
    await author.publish(payload)
    const remote = author.asLink()
    let reads = 0
    reader.connect({ ...remote, read: async () => [], readPayload: async (id) => { reads += 1; return remote.readPayload(id) } })
    await reader.catchUp()
    expect(reads).toBe(0)
    expect(await reader.history()).toEqual([])
    expect(await reader.getPayload(hash)).toEqual(payload)
    expect(reads).toBe(1)
    reader.disconnect(author.identity)
    expect(await reader.getPayload(hash)).toEqual(payload)
    relay.connect({ ...reader.asLink(), read: async () => [] })
    await relay.catchUp()
    expect(await relay.getPayload(hash)).toEqual(payload)
    expect(await relay.history()).toEqual([])
  })

  it('forwards signed history through another peer without an authority', async () => {
    const [author, relay, reader] = await Promise.all([peer(), peer(), peer()])
    connectInProcess(author, relay)
    connectInProcess(relay, reader)
    reader.requestFeed(author.identity)
    const proposal = await author.publish(Uint8Array.of(1, 7, 3))
    await relay.catchUp()
    await reader.catchUp()
    expect(await reader.get(proposal.id)).toMatchObject({ id: proposal.id, author: author.identity, sequence: 1n, payload: proposal.payload })
    expect(await reader.feedContiguousThrough(author.identity)).toBe(1n)
    expect((await reader.status()).peers).not.toContain(author.identity)
  })

  it('catches up from retained bytes after missed hints and does not duplicate a second path', async () => {
    const [author, relay, reader] = await Promise.all([peer(), peer(), peer()])
    const proposal = await author.publish(Uint8Array.of(8))
    connectInProcess(author, relay)
    await relay.catchUp()
    connectInProcess(author, reader)
    connectInProcess(relay, reader)
    await reader.catchUp()
    expect((await reader.history()).filter((item) => item.id === proposal.id)).toHaveLength(1)
    reader.disconnect(author.identity)
    reader.disconnect(relay.identity)
    const later = await author.publish(Uint8Array.of(9))
    reader.connect(author.asLink())
    await reader.catchUp()
    expect(await reader.get(later.id)).toBeDefined()
    expect((await reader.history()).map((item) => item.sequence)).toEqual([1n, 2n])
  })

  it('relays immutable evidence without authoring another feed record', async () => {
    const [author, relay, reader] = await Promise.all([peer(), peer(), peer()])
    const proof = await author.putEvidence(Uint8Array.of(5, 9, 2))
    connectInProcess(author, relay)
    await relay.catchUp()
    author.disconnect(relay.identity)
    relay.disconnect(author.identity)
    connectInProcess(relay, reader)
    await reader.catchUp()
    expect(await reader.evidenceHistory()).toEqual([proof])
    expect(await reader.history()).toEqual([])
    expect(await reader.putEvidence(proof.bytes)).toEqual(proof)
    expect(await reader.evidenceHistory()).toHaveLength(1)
  })

  it('serializes concurrent local signing so no feed sequence forks', async () => {
    const author = await peer()
    const records = await Promise.all(Array.from({ length: 10 }, (_, index) => author.publish(Uint8Array.of(index))))
    expect(records.map((record) => record.sequence)).toEqual(Array.from({ length: 10 }, (_, index) => BigInt(index + 1)))
    expect((await author.history()).length).toBe(10)
  })

  it('does not accept another author as the requested feed', async () => {
    const [author, attacker, reader] = await Promise.all([peer(), peer(), peer()])
    await attacker.publish(Uint8Array.of(1))
    reader.connect({ identity: author.identity, readEvidence: async () => [], readPayload: async () => null, read: (_feed, after, limit) => attacker.asLink().read(attacker.identity, after, limit), async *watch() {} })
    await expect(reader.catchUp()).rejects.toThrow('FEED_RANGE_AUTHOR_MISMATCH')
    expect(await reader.history()).toEqual([])
  })
})
