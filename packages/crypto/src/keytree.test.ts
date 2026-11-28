import { describe, expect, it } from 'vitest'
import { sha256 } from '@noble/hashes/sha256'
import { bytesToHex, utf8 } from '@chronolog/protocol'
import {
  KEY_TREE_SUITE_X25519,
  KEY_TREE_SUITE_XWING,
  buildTreeEpochUpdate,
  epochKeyCommitment,
  generateX25519KeyPair,
  generateXWingKeyPair,
  openTreeEpoch,
  readKeyTreeFromCas,
  writeKeyTreeToCas,
  type KeyTreeEpochPayload,
  type KeyTreeSuite,
} from './index.js'

const SCOPE = 'a'.repeat(64)

interface Member {
  readonly publicKey: string
  readonly wrap: Awaited<ReturnType<typeof generateX25519KeyPair>>
  readonly pq?: ReturnType<typeof generateXWingKeyPair>
  readonly seeds: Map<string, Uint8Array>
}

let counter = 0
async function makeMember(options: { readonly pq?: boolean; readonly publicKey?: string } = {}): Promise<Member> {
  counter++
  const publicKey = options.publicKey ?? bytesToHex(sha256(utf8(`member-${counter}-${Math.random()}`)))
  return {
    publicKey,
    wrap: await generateX25519KeyPair(false),
    ...(options.pq ? { pq: generateXWingKeyPair() } : {}),
    seeds: new Map(),
  }
}

function leafInput(m: Member, opts: { readonly x25519?: boolean; readonly pq?: boolean } = { x25519: true, pq: true }) {
  return {
    publicKey: m.publicKey,
    ...(opts.x25519 !== false ? { wrapKey: bytesToHex(m.wrap.publicKeyBytes) } : {}),
    ...(opts.pq !== false && m.pq ? { pqWrapKey: bytesToHex(m.pq.publicKey) } : {}),
  }
}

async function open(m: Member, payload: KeyTreeEpochPayload, keyCommitment: string) {
  const opened = await openTreeEpoch({
    scope: SCOPE,
    payload,
    keyCommitment,
    wrapPrivateKey: m.wrap.privateKey,
    wrapPublicKeyHex: bytesToHex(m.wrap.publicKeyBytes),
    ...(m.pq ? { pqSecretKey: m.pq.secretKey, pqPublicKeyHex: bytesToHex(m.pq.publicKey) } : {}),
    cachedNodeSeeds: m.seeds,
  })
  if (opened !== null) for (const [h, s] of opened.derivedSeeds) m.seeds.set(h, s)
  return opened
}

function memoryCas() {
  const store = new Map<string, Uint8Array>()
  return {
    store,
    put: async (bytes: Uint8Array) => {
      const h = bytesToHex(sha256(bytes))
      store.set(h, bytes)
      return h
    },
    get: async (h: string) => store.get(h) ?? null,
  }
}

/** Small deterministic PRNG (mulberry32) for reproducible property runs. */
function prng(seed: number): () => number {
  let a = seed >>> 0
  return () => {
    a = (a + 0x6d2b79f5) >>> 0
    let t = a
    t = Math.imul(t ^ (t >>> 15), t | 1)
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61)
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296
  }
}

describe('Key-Tagged TreeKEM', () => {
  it('lets every member open, round-trips through CAS, and verifies the epoch commitment', async () => {
    const members = await Promise.all([0, 1, 2, 3, 4].map(() => makeMember()))
    const built = await buildTreeEpochUpdate({
      scope: SCOPE, epoch: 0, updaterPublicKey: members[0]!.publicKey, activeMembers: members.map(m => leafInput(m)),
    })
    expect(built.payload.leafCount).toBe(8)
    const commitment = epochKeyCommitment(built.epochKey)
    const cas = memoryCas()
    const rootHash = await writeKeyTreeToCas(built.payload, cas.put)
    const read = await readKeyTreeFromCas(rootHash, cas.get)
    expect(read.ok).toBe(true)
    if (!read.ok) return
    expect(read.payload.memberLeaves).toEqual(built.payload.memberLeaves)
    for (const m of members) {
      const opened = await open(m, read.payload, commitment)
      expect(opened?.epochKey).toEqual(built.epochKey)
    }
    // Wrong commitment: nobody accepts the key.
    expect(await open(members[1]!, read.payload, 'f'.repeat(64))).toBeNull()
  })

  it('tries every candidate box so one junk box cannot deny a member', async () => {
    const members = await Promise.all([0, 1, 2, 3].map(() => makeMember()))
    const built = await buildTreeEpochUpdate({
      scope: SCOPE, epoch: 0, updaterPublicKey: members[0]!.publicKey, activeMembers: members.map(m => leafInput(m)),
    })
    const commitment = epochKeyCommitment(built.epochKey)
    const victim = members[3]!
    const victimSlot = built.payload.memberLeaves[victim.publicKey]!
    const victimLeaf = built.payload.nodes[String(built.payload.leafCount + victimSlot)]!
    // A junk box sealed to the victim's leaf with a random seed, placed before the genuine boxes.
    const junkSource = await buildTreeEpochUpdate({
      scope: SCOPE, epoch: 0, updaterPublicKey: victim.publicKey, activeMembers: [leafInput(victim), leafInput(members[0]!)],
    })
    const junk = junkSource.payload.copathBoxes.find(b => b.targetPubKeyHash === victimLeaf.pubKeyHash)!
    const forged = { ...junk, targetNode: victimLeaf.index, pathNode: Math.floor(victimLeaf.index / 2) }
    const poisoned: KeyTreeEpochPayload = { ...built.payload, copathBoxes: [forged, ...built.payload.copathBoxes] }
    const opened = await open(victim, poisoned, commitment)
    expect(opened?.epochKey).toEqual(built.epochKey)
  })

  it('rejects a path whose nodes are missing or do not match (no silent acceptance of unverifiable seeds)', async () => {
    const members = await Promise.all([0, 1, 2, 3].map(() => makeMember()))
    const built = await buildTreeEpochUpdate({
      scope: SCOPE, epoch: 0, updaterPublicKey: members[0]!.publicKey, activeMembers: members.map(m => leafInput(m)),
    })
    const commitment = epochKeyCommitment(built.epochKey)
    const nodes = { ...built.payload.nodes }
    delete nodes['1']
    expect(await open(members[2]!, { ...built.payload, nodes }, commitment)).toBeNull()
  })

  it('rejects (never drops) members that do not fit the tree suite, and accepts PQ-only members in X25519 trees', async () => {
    const plain = await makeMember()
    const pq = await makeMember({ pq: true })
    await expect(buildTreeEpochUpdate({
      scope: SCOPE, epoch: 0, updaterPublicKey: pq.publicKey, suite: KEY_TREE_SUITE_XWING,
      activeMembers: [leafInput(pq), leafInput(plain)],
    })).rejects.toMatchObject({ code: 'INVALID_KEY' })

    const pqOnly = await makeMember({ pq: true })
    const built = await buildTreeEpochUpdate({
      scope: SCOPE, epoch: 0, updaterPublicKey: plain.publicKey, suite: KEY_TREE_SUITE_X25519,
      activeMembers: [leafInput(plain), leafInput(pqOnly, { x25519: false, pq: true })],
    })
    expect(Object.keys(built.payload.memberLeaves).sort()).toEqual([plain.publicKey, pqOnly.publicKey].sort())
    expect((await open(pqOnly, built.payload, epochKeyCommitment(built.epochKey)))?.epochKey).toEqual(built.epochKey)
  })

  it('builds hybrid PQ X-Wing trees that every member opens', async () => {
    const members = await Promise.all([0, 1, 2].map(() => makeMember({ pq: true })))
    const built = await buildTreeEpochUpdate({
      scope: SCOPE, epoch: 0, updaterPublicKey: members[0]!.publicKey, activeMembers: members.map(m => leafInput(m)),
    })
    expect(built.payload.suite).toBe(KEY_TREE_SUITE_XWING)
    const cas = memoryCas()
    const read = await readKeyTreeFromCas(await writeKeyTreeToCas(built.payload, cas.put), cas.get)
    expect(read.ok).toBe(true)
    if (!read.ok) return
    for (const m of members) expect((await open(m, read.payload, epochKeyCommitment(built.epochKey)))?.epochKey).toEqual(built.epochKey)
  })

  it('assigns new slots in bytewise publicKey order and gives a non-member updater a full member path', async () => {
    const keys = ['0'.repeat(64), '1'.repeat(64), 'a'.repeat(64), 'f'.repeat(64)]
    const members = await Promise.all([...keys].reverse().map(k => makeMember({ publicKey: k })))
    const outsider = await makeMember()
    const built = await buildTreeEpochUpdate({
      scope: SCOPE, epoch: 0, updaterPublicKey: outsider.publicKey, activeMembers: members.map(m => leafInput(m)),
    })
    expect(keys.map(k => built.payload.memberLeaves[k])).toEqual([0, 1, 2, 3])
    for (const m of members) expect((await open(m, built.payload, epochKeyCommitment(built.epochKey)))?.epochKey).toEqual(built.epochKey)
  })

  it('detects tampering with tree nodes or the leaf directory in CAS', async () => {
    const members = await Promise.all([0, 1, 2].map(() => makeMember()))
    const built = await buildTreeEpochUpdate({
      scope: SCOPE, epoch: 0, updaterPublicKey: members[0]!.publicKey, activeMembers: members.map(m => leafInput(m)),
    })
    const cas = memoryCas()
    const rootHash = await writeKeyTreeToCas(built.payload, cas.put)
    const root = JSON.parse(new TextDecoder().decode(cas.store.get(rootHash))) as { leafChunkRefs: string[] }
    // Leaf directory that omits a member that still holds a leaf.
    const chunkHash = root.leafChunkRefs[0]!.slice('cas:sha256-'.length)
    const chunk = JSON.parse(new TextDecoder().decode(cas.store.get(chunkHash))) as { format: string; leaves: unknown[] }
    const forgedChunk = await cas.put(utf8(JSON.stringify({ ...chunk, leaves: chunk.leaves.slice(1) })))
    const forgedRoot = await cas.put(utf8(JSON.stringify({ ...root, leafChunkRefs: [`cas:sha256-${forgedChunk}`] })))
    expect(await readKeyTreeFromCas(forgedRoot, cas.get)).toMatchObject({ ok: false, corrupt: true })
    // Missing chunk reports the exact hash.
    const missing = await readKeyTreeFromCas(rootHash, async h => (h === chunkHash ? null : cas.store.get(h) ?? null))
    expect(missing).toEqual({ ok: false, missingHashes: [chunkHash] })
  })

  for (const seed of [1, 2, 3]) {
    it(`property: random add/remove/rekey histories keep members in and removed members out (seed ${seed})`, async () => {
      const rand = prng(seed)
      const pool = await Promise.all(Array.from({ length: 10 }, () => makeMember()))
      let active: Member[] = pool.slice(0, 3)
      const removed: Member[] = []
      let previousTree: KeyTreeEpochPayload | null = null
      const cas = memoryCas()
      const suite: KeyTreeSuite = KEY_TREE_SUITE_X25519
      for (let epoch = 0; epoch < 14; epoch++) {
        const r = rand()
        const candidates = pool.filter(m => !active.includes(m) && !removed.includes(m))
        if (r < 0.4 && candidates.length > 0) {
          active = [...active, candidates[Math.floor(rand() * candidates.length)]!]
        } else if (r < 0.8 && active.length > 1) {
          const victim = active[Math.floor(rand() * active.length)]!
          active = active.filter(m => m !== victim)
          removed.push(victim)
        } else if (r < 0.9) {
          // Re-key: the member rotates its wrap key; the retired key (and its cached seeds) must lose access.
          const idx = Math.floor(rand() * active.length)
          const old = active[idx]!
          const fresh = await makeMember({ publicKey: old.publicKey })
          active = active.map((m, i) => (i === idx ? fresh : m))
          removed.push(old)
        }
        const updater = active[Math.floor(rand() * active.length)]!
        const built: Awaited<ReturnType<typeof buildTreeEpochUpdate>> = await buildTreeEpochUpdate({
          scope: SCOPE, epoch, updaterPublicKey: updater.publicKey, activeMembers: active.map(m => leafInput(m)), previousTree, suite,
        })
        for (const [h, s] of built.derivedSeeds) updater.seeds.set(h, s)
        const read = await readKeyTreeFromCas(await writeKeyTreeToCas(built.payload, cas.put), cas.get)
        expect(read.ok).toBe(true)
        if (!read.ok) return
        previousTree = read.payload
        expect(Object.keys(read.payload.memberLeaves).sort()).toEqual(active.map(m => m.publicKey).sort())
        const commitment = epochKeyCommitment(built.epochKey)
        // Box count stays O(log N) + 1 (plus the resolution of blank siblings).
        expect(read.payload.copathBoxes.length).toBeLessThanOrEqual(read.payload.leafCount)
        for (const m of active) {
          const opened = await open(m, read.payload, commitment)
          expect(opened?.epochKey).toEqual(built.epochKey)
        }
        for (const m of removed) {
          expect(await open(m, read.payload, commitment)).toBeNull()
        }
      }
    }, 60_000)
  }
})
