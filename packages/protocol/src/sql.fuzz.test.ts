import { describe, expect, it } from 'vitest'

import { platformOp } from './platform.js'
import {
  decodeSqlTransactionProgram,
  encodeSqlTransactionProgram,
  type SqlTransactionProgram,
} from './program.js'
import { sqlStatement, sqlValue } from './sql.js'

const key = (fill: number): Uint8Array => new Uint8Array(32).fill(fill)

const fixture: SqlTransactionProgram = {
  version: 2,
  steps: [
    sqlStatement("SELECT chronolog_assert(? > 0, 'positive')", [7n]),
    sqlStatement('INSERT INTO t VALUES (:a, :b, :c, :d)', { a: sqlValue.real(1.5), b: 'text', c: new Uint8Array([1, 2]), d: null }),
    platformOp.grant({ table: 't', grantee: key(2), operations: ['update', 'delete'], rowKey: [7n, 'k'], columns: ['b'] }),
    platformOp.createCollective({ governance: { insert: 'member', update: 'member', delete: 'admin' }, invitees: [key(3)] }),
    platformOp.setMembers(key(4), [{ member: key(5), role: 'admin' }, { member: key(6), role: 'remove' }]),
    platformOp.transferRow({ table: 't', rowKey: [1n], toOwner: key(7), carry: true }),
    platformOp.transferAll({ toOwner: key(8) }),
    platformOp.seedRows('t', ['a', 'chronolog_owner'], [[1n, key(9)]]),
  ],
}

describe('transaction program mutation fuzz corpus', () => {
  it('accepts only canonical mutated programs', () => {
    const original = encodeSqlTransactionProgram(fixture)
    let state = 0x52534c54
    for (let index = 0; index < 4_000; index += 1) {
      state = next(state)
      const candidate = mutate(original, state)
      try {
        const decoded = decodeSqlTransactionProgram(candidate)
        expect(encodeSqlTransactionProgram(decoded)).toEqual(candidate)
      } catch (error) {
        expect(error).toBeInstanceOf(Error)
      }
    }
  })
})

function mutate(original: Uint8Array, seed: number): Uint8Array {
  const mode = seed % 4
  if (mode === 0) return original.slice(0, seed % original.length)
  if (mode === 1) {
    const result = original.slice()
    const offset = seed % result.length
    result[offset] = result[offset]! ^ (1 << ((seed >>> 8) % 8))
    return result
  }
  if (mode === 2) {
    const result = new Uint8Array(original.length + 1)
    result.set(original)
    result[result.length - 1] = seed & 0xff
    return result
  }
  const result = original.slice()
  const first = seed % result.length
  const second = (seed >>> 8) % result.length
  ;[result[first], result[second]] = [result[second]!, result[first]!]
  return result
}

function next(state: number): number {
  let value = state | 0
  value ^= value << 13
  value ^= value >>> 17
  value ^= value << 5
  return value >>> 0
}
