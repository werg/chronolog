import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import {
  DeterministicMaterializer,
  createDoltLiteMaterializationRuntime,
  createDoltLiteExecutionManifest,
} from '@chronolog/materializer-doltlite'
import { ChronologNode, type MembershipResolver } from '@chronolog/node-core'
import { equalBytes, generateEd25519KeyPair, type Ed25519KeyPair } from '@chronolog/protocol'
import { type ChronologTransport, MemoryTransportNetwork } from '@chronolog/transport-ssb'
import { afterEach, describe, expect, it } from 'vitest'

const cleanup: Array<() => Promise<void>> = []
afterEach(async () => { for (const close of cleanup.splice(0).reverse()) await close() })

// Regression: a transport closes a subscriber whose buffer overflows (the
// consumer fell behind during a replication burst). The node's consume loop
// then ended silently and the node never ingested another live record until
// restart (chaos stress: one node stuck with hundreds of records unread).
describe('transport subscription restart', () => {
  it('resubscribes when the transport ends a subscription and keeps ingesting', async () => {
    const network = new MemoryTransportNetwork()
    const [a, b] = await Promise.all([generateEd25519KeyPair(), generateEd25519KeyPair()])
    const capability = bytes32(4)
    const membership = validatorMembership(a, b, capability)
    const innerA = network.createNode('a')
    let subscriptions = 0
    const transportA: ChronologTransport = {
      identity: innerA.identity,
      publish: (payload, options) => innerA.publish(payload, options),
      get: (id) => innerA.get(id),
      getPayload: (hash) => innerA.getPayload(hash),
      history: () => innerA.history(),
      // The first subscription ends at once, as an overflowing subscriber would.
      subscribe: (signal) => (subscriptions += 1) === 1 ? (async function* () { /* ended */ })() : innerA.subscribe(signal),
      status: () => innerA.status(),
      feedContiguousThrough: (feedId) => innerA.feedContiguousThrough(feedId),
      close: () => innerA.close(),
    }
    const nodeA = await node('a', a, transportA, membership, capability)
    const nodeB = await node('b', b, network.createNode('b'), membership, capability)
    network.connectAll()
    await nodeB.publishHeartbeat()
    const deadline = Date.now() + 10_000
    while (!hasHeartbeat(nodeA, b.publicKeyBytes)) {
      if (Date.now() > deadline) throw new Error('node A never ingested the live record from node B')
      await new Promise((resolve) => setTimeout(resolve, 50))
    }
    expect(nodeA.subscriptionRestarts).toBeGreaterThanOrEqual(1)
    expect(subscriptions).toBeGreaterThanOrEqual(2)
  })

  it('recovers records a live subscription silently missed from transport history', async () => {
    const network = new MemoryTransportNetwork()
    const [a, b] = await Promise.all([generateEd25519KeyPair(), generateEd25519KeyPair()])
    const capability = bytes32(4)
    const membership = validatorMembership(a, b, capability)
    const innerA = network.createNode('a')
    let subscriptions = 0, historyReads = 0
    const dropped = new Set<string>()
    const transportA: ChronologTransport = {
      identity: innerA.identity,
      publish: (payload, options) => innerA.publish(payload, options),
      get: (id) => innerA.get(id),
      getPayload: (hash) => innerA.getPayload(hash),
      history: () => { historyReads += 1; return innerA.history() },
      // The first subscription stays open but drops every live record from b.
      subscribe: (signal) => (subscriptions += 1) === 1
        ? (async function* () {
            for await (const record of innerA.subscribe(signal)) {
              if (record.author === 'b') dropped.add(record.id)
              else yield record
            }
          })()
        : innerA.subscribe(signal),
      status: () => innerA.status(),
      feedContiguousThrough: (feedId) => innerA.feedContiguousThrough(feedId),
      close: () => innerA.close(),
    }
    const nodeA = await node('a2', a, transportA, membership, capability)
    const nodeB = await node('b2', b, network.createNode('b'), membership, capability)
    network.connectAll()
    await nodeB.publishHeartbeat()
    const missing = nodeB.controlStore.listHeartbeats().find(heartbeat => equalBytes(heartbeat.validatorId, b.publicKeyBytes))!
    const previousHistoryReads = historyReads
    const deadline = Date.now() + 40_000
    // Automatic local heartbeats continue to arrive. Only B's verified,
    // contiguous heartbeat establishes that the missing feed was recovered.
    while (!hasHeartbeat(nodeA, b.publicKeyBytes, missing.validatorFeedSequence)) {
      if (Date.now() > deadline) throw new Error('node A never recovered the missed record')
      await new Promise((resolve) => setTimeout(resolve, 200))
    }
    expect(dropped.has(new TextDecoder().decode(missing.heartbeatId))).toBe(true)
    expect(historyReads).toBeGreaterThan(previousHistoryReads)
    expect(nodeA.subscriptionRestarts).toBeGreaterThanOrEqual(1)
  }, 60_000)
})

function validatorMembership(a: Ed25519KeyPair, b: Ed25519KeyPair, capability: Uint8Array): MembershipResolver {
  return {
    canWrite: () => false,
    canValidate: ({ validatorId, validatorCapability }) =>
      (equalBytes(validatorId, a.publicKeyBytes) || equalBytes(validatorId, b.publicKeyBytes)) && equalBytes(validatorCapability, capability),
    canUseTransportAuthor: ({ role, transportAuthor, signingId, validatorCapability }) =>
      role === 'validator' && validatorCapability !== undefined && equalBytes(validatorCapability, capability) &&
      (transportAuthor === 'a' && equalBytes(signingId, a.publicKeyBytes) ||
        transportAuthor === 'b' && equalBytes(signingId, b.publicKeyBytes)),
    threshold: () => 1,
  }
}

function hasHeartbeat(node: ChronologNode, validatorId: Uint8Array, throughSequence = 1n): boolean {
  return node.controlStore.listHeartbeats().some(heartbeat => equalBytes(heartbeat.validatorId, validatorId) &&
    heartbeat.feedContiguous && heartbeat.validatorFeedSequence >= throughSequence)
}

async function node(name: string, identity: Ed25519KeyPair, transport: ChronologTransport, membership: MembershipResolver, capability: Uint8Array): Promise<ChronologNode> {
  const directory = await mkdtemp(join(tmpdir(), `chronolog-subscription-${name}-`))
  const materializer = await DeterministicMaterializer.open({
    path: join(directory, 'application.db'),
    executionManifest: createDoltLiteExecutionManifest(),
    rootAdministrator: identity.publicKeyBytes,
  })
  const created = new ChronologNode({
    groupId: bytes32(1),
    membershipRevision: bytes32(2),
    validationPolicy: bytes32(3),
    identity,
    transport,
    materialization: createDoltLiteMaterializationRuntime(materializer),
    membership,
    validator: { capabilityId: capability, cutoffLagMs: 1_000 },
  })
  cleanup.push(async () => { await created.close(); await rm(directory, { recursive: true, force: true }) })
  await created.start()
  return created
}

function bytes32(seed: number): Uint8Array { return Uint8Array.from({ length: 32 }, (_value, index) => (seed + index) & 0xff) }
