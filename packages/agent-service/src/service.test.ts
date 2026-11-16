import { MemoryOperationStore } from '@chronolog/node-core'
import { utf8 } from '@chronolog/protocol'
import { describe, expect, it } from 'vitest'

import { CheckpointStore } from './checkpoint.js'
import { ResidentAgentService, waitForAbortableDelay } from './service.js'

describe('resident lifecycle and checkpoint contract', () => {
  it('commits projection state and its cursor in the same value and rejects a changed binding', async () => {
    const backing = new MemoryOperationStore()
    let fail = false
    const store = { get: (key: string) => backing.get(key), put: async (key: string, bytes: Uint8Array) => {
      if (fail) throw new Error('crash before commit')
      await backing.put(key, bytes)
    } }
    const checkpoint = new CheckpointStore(store, { id: 'projection', binding: utf8('group/history/filter/reducer-v1') })
    await checkpoint.commit({ cursor: 'c:1', revision: 'r:1', state: utf8('first') })
    fail = true
    await expect(checkpoint.commit({ cursor: 'c:2', revision: 'r:2', state: utf8('second') })).rejects.toThrow('crash before commit')
    expect(await checkpoint.load()).toEqual({ cursor: 'c:1', revision: 'r:1', state: utf8('first') })
    const changed = new CheckpointStore(store, { id: 'projection', binding: utf8('group/history/filter/reducer-v2') })
    await expect(changed.load()).rejects.toThrow('CHECKPOINT_BINDING_MISMATCH')
  })

  it('runs resident loops concurrently and aborts peers when a task fails', async () => {
    let stopped = false
    const service = new ResidentAgentService([
      { id: 'sync', run: async (signal) => { await waitForAbortableDelay(60_000, signal); stopped = true } },
      { id: 'worker', run: async () => { throw new Error('provider outcome uncertain') } },
    ])
    await expect(service.run()).rejects.toThrow('RESIDENT_TASK_FAILED: worker')
    expect(stopped).toBe(true)
    expect(service.status).toEqual({ running: false, failedTask: 'worker' })
  })

  it('stops cleanly on explicit shutdown and rejects duplicate owners', async () => {
    const service = new ResidentAgentService([{ id: 'sync', run: (signal) => waitForAbortableDelay(60_000, signal) }])
    const running = service.run()
    service.stop()
    await running
    expect(service.status.failedTask).toBeNull()
    expect(() => new ResidentAgentService([{ id: 'same', run: async () => {} }, { id: 'same', run: async () => {} }]))
      .toThrow('RESIDENT_TASK_DUPLICATE')
  })
})
