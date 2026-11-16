import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import {
  DeterministicMaterializer,
  createDoltLiteMaterializationRuntime,
  createDoltLiteExecutionManifest,
} from '@chronolog/materializer-doltlite'
import { ChronologNode, type MembershipResolver } from '@chronolog/node-core'
import { equalBytes, generateEd25519KeyPair } from '@chronolog/protocol'
import { type ChronologTransport, MemoryTransportNetwork } from '@chronolog/transport-ssb'
import { afterEach, describe, expect, it } from 'vitest'

const cleanup: Array<() => Promise<void>> = []
afterEach(async () => { for (const close of cleanup.splice(0).reverse()) await close() })

// Regression: heartbeat ingestion called transport.status() once per record.
// On ssb-db2 that runs a full count() over the log and waits for index drain,
// so per-heartbeat cost grew with history; under the chaos smoke scenario
// (three validators, 1s heartbeats) ingestion fell permanently behind.
describe('heartbeat ingestion cost', () => {
  it('determines feed contiguity without a full transport status scan', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'chronolog-heartbeat-cost-'))
    const identity = await generateEd25519KeyPair()
    const capability = bytes32(4)
    const materializer = await DeterministicMaterializer.open({
      path: join(directory, 'application.db'),
      executionManifest: createDoltLiteExecutionManifest(),
      rootAdministrator: identity.publicKeyBytes,
    })
    const membership: MembershipResolver = {
      canWrite: ({ writerId }) => equalBytes(writerId, identity.publicKeyBytes),
      canValidate: ({ validatorId, validatorCapability }) => equalBytes(validatorId, identity.publicKeyBytes) && equalBytes(validatorCapability, capability),
      threshold: () => 1,
    }
    const inner = new MemoryTransportNetwork().createNode('heartbeat-cost')
    let statusCalls = 0
    let contiguityCalls = 0
    const transport: ChronologTransport = {
      identity: inner.identity,
      publish: (payload, options) => inner.publish(payload, options),
      get: (id) => inner.get(id),
      getPayload: (hash) => inner.getPayload(hash),
      history: () => inner.history(),
      subscribe: (signal) => inner.subscribe(signal),
      status: () => { statusCalls += 1; return inner.status() },
      feedContiguousThrough: (feedId) => { contiguityCalls += 1; return inner.feedContiguousThrough(feedId) },
      close: () => inner.close(),
    }
    const node = new ChronologNode({
      groupId: bytes32(1),
      membershipRevision: bytes32(2),
      validationPolicy: bytes32(3),
      identity,
      transport,
      materialization: createDoltLiteMaterializationRuntime(materializer),
      membership,
      validator: { capabilityId: capability, cutoffLagMs: 1_000 },
    })
    cleanup.push(async () => { await node.close(); await rm(directory, { recursive: true, force: true }) })
    await node.start()

    const before = statusCalls
    for (let index = 0; index < 5; index += 1) await node.publishHeartbeat()

    expect(contiguityCalls).toBeGreaterThanOrEqual(5)
    expect(statusCalls - before).toBe(0)
  })
})

function bytes32(seed: number): Uint8Array { return Uint8Array.from({ length: 32 }, (_value, index) => (seed + index) & 0xff) }
