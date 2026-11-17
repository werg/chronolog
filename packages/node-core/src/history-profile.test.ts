import { createEventMaterializationRuntime } from '@chronolog/materializer'
import { generateEd25519KeyPair } from '@chronolog/protocol'
import { MemoryTransportNetwork } from '@chronolog/transport-ssb'
import { expect, it, vi } from 'vitest'

import { ChronologNode } from './node.js'
import { MemoryOperationStore } from './operations.js'

it('rejects a real generation materializer before exposing chronological final events', async () => {
  const store = new MemoryOperationStore(), materialization = await createEventMaterializationRuntime({
    store, namespace: 'generation', historyProfile: 'peer-generation-v1',
  })
  const get = vi.spyOn(store, 'get'), put = vi.spyOn(store, 'put')
  const transport = new MemoryTransportNetwork().createNode('profile-admission')
  try {
    const identity = await generateEd25519KeyPair()
    expect(() => new ChronologNode({ identity, groupId: new Uint8Array(32).fill(1),
      membershipRevision: new Uint8Array(32).fill(2), validationPolicy: new Uint8Array(32).fill(3),
      operationStore: store, transport, materialization,
      membership: { canWrite: () => true, canValidate: () => true, threshold: () => 1 },
    })).toThrow('NODE_HISTORY_PROFILE_UNSUPPORTED')
    expect(get).not.toHaveBeenCalled(); expect(put).not.toHaveBeenCalled()
  } finally { await materialization.close(); await transport.close() }
})
