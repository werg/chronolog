import { StrictMode, createElement } from 'react'
import { act, create, type ReactTestRenderer } from 'react-test-renderer'
import { describe, expect, it } from 'vitest'
import { StreamResource, type ChronologClient, type LiveQueryValue, type LocalSqlInput } from '@chronolog/client'

import { useMyTeams, type OwnershipListState } from './ownership.js'

;(globalThis as typeof globalThis & { IS_REACT_ACT_ENVIRONMENT: boolean }).IS_REACT_ACT_ENVIRONMENT = true

describe('ownership hooks', () => {
  it('queries teams for this node\'s key once it is known and decodes the rows', async () => {
    const me = new Uint8Array(32).fill(9)
    const team = new Uint8Array(32).fill(4)
    const queries: { readonly sql: string; readonly parameters: readonly LocalSqlInput[] }[] = []
    let resolveIdentity: (key: Uint8Array) => void = () => undefined
    const identity = new Promise<Uint8Array>((resolve) => { resolveIdentity = resolve })
    const client = {
      identity: () => identity,
      queryResourceKey: (sql: string, parameters: readonly LocalSqlInput[]) => `${sql}|${parameters.length}`,
      liveQuery(sql: string, parameters: readonly LocalSqlInput[]) {
        queries.push({ sql, parameters })
        const value = {
          type: 'snapshot',
          result: { columns: [], rows: [[team, 'admin', 'member', 'member', 'admin']], truncated: false, consensusSafe: false },
        } as unknown as LiveQueryValue
        return new StreamResource<LiveQueryValue>({
          // A live stream that stays open until it is disposed.
          open: async function* (_cursor, signal) {
            yield value
            await new Promise<void>((resolve) => { signal.addEventListener('abort', () => resolve(), { once: true }) })
          },
          cursor: () => undefined,
        })
      },
    } as unknown as ChronologClient
    const states: OwnershipListState<unknown>[] = []
    function Probe() {
      states.push(useMyTeams({ client }))
      return null
    }

    let renderer: ReactTestRenderer | undefined
    await act(async () => { renderer = create(createElement(StrictMode, null, createElement(Probe))) })
    expect(states.at(-1)?.status).toBe('loading')
    expect(queries).toHaveLength(0)

    await act(async () => { resolveIdentity(me); await identity })
    expect(queries.at(-1)?.parameters).toEqual([me])
    expect(queries.at(-1)?.sql).toContain("m.state = 'active'")
    expect(states.at(-1)).toEqual({
      status: 'ready',
      rows: [{ teamId: team, role: 'admin', governance: { insert: 'member', update: 'member', delete: 'admin' } }],
    })
    await act(async () => { renderer?.unmount() })
  })
})
