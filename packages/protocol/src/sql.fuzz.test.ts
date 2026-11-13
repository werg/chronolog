import { describe, expect, it } from 'vitest'

import {
  decodeSqlTransactionProgram,
  encodeSqlTransactionProgram,
  sqlStatement,
  sqlValue,
  type SqlTransactionProgram,
} from './sql.js'

const fixture: SqlTransactionProgram = {
  version: 1,
  statements: [
    sqlStatement("SELECT chronolog_assert(? > 0, 'positive')", [7n]),
    sqlStatement('INSERT INTO t VALUES (:a, :b, :c, :d)', { a: sqlValue.real(1.5), b: 'text', c: new Uint8Array([1, 2]), d: null }),
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
