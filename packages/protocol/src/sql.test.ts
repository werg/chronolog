import { describe, expect, it } from 'vitest'

import {
  createExecutionManifest,
  decodeExecutionManifest,
  decodeChangeProgram,
  encodeCanonicalCbor,
  encodeExecutionManifest,
  encodeChangeProgram,
  sqlStatement,
  sqlValue,
  sqlValueFromCanonicalCbor,
  sqlValueToCanonicalCbor,
  toSqlValue,
  type ChangeProgram,
} from './index.js'

const program: ChangeProgram = {
  version: 3,
  steps: [
    sqlStatement('CREATE TABLE t (a, b, c, d, e)'),
    sqlStatement("SELECT chronolog_assert(NOT EXISTS (SELECT 1 FROM t), 'empty')"),
    sqlStatement('INSERT INTO t VALUES (?, ?, ?, ?, ?)', [null, 9_007_199_254_740_993n, sqlValue.real(1), 'é', new Uint8Array(0)]),
    sqlStatement('UPDATE t SET a = :a WHERE b = @b', { a: -0.5, '@b': 1n }),
  ],
}

describe('SQL transaction programs', () => {
  it('round-trips ordinary statements with every SQLite value class', () => {
    const encoded = encodeChangeProgram(program)
    const decoded = decodeChangeProgram(encoded)
    expect(decoded).toEqual(program)
    expect(encodeChangeProgram(decoded)).toEqual(encoded)
  })

  it('keeps integral REALs distinct from INTEGERs', () => {
    const real = sqlValueToCanonicalCbor(sqlValue.real(1))
    const integer = sqlValueToCanonicalCbor(sqlValue.integer(1))
    expect(encodeCanonicalCbor(real)).not.toEqual(encodeCanonicalCbor(integer))
    expect(sqlValueFromCanonicalCbor(real)).toEqual({ kind: 'real', value: 1 })
    expect(toSqlValue(1)).toEqual({ kind: 'integer', value: 1n })
    expect(toSqlValue(1.25)).toEqual({ kind: 'real', value: 1.25 })
    expect(toSqlValue(true)).toEqual({ kind: 'integer', value: 1n })
  })

  it('names positional and named parameters the way SQLite does', () => {
    expect(sqlStatement('SELECT :x', { x: 1n }).bindings[0]!.parameter).toEqual({ kind: 'name', name: ':x' })
    expect(sqlStatement('SELECT $x', { $x: 1n }).bindings[0]!.parameter).toEqual({ kind: 'name', name: '$x' })
    expect(sqlStatement('SELECT ?, ?', [1n, 2n]).bindings.map((binding) => binding.parameter))
      .toEqual([{ kind: 'index', index: 1 }, { kind: 'index', index: 2 }])
  })

  it('rejects empty programs, empty SQL, NUL, non-finite REALs, out-of-range INTEGERs and duplicate bindings', () => {
    expect(() => encodeChangeProgram({ version: 3, steps: [] })).toThrow()
    expect(() => encodeChangeProgram({ version: 3, steps: [{ sql: '  ', bindings: [] }] })).toThrow()
    expect(() => sqlStatement('SELECT 1\0')).toThrow()
    expect(() => sqlValue.real(Number.NaN)).toThrow()
    expect(() => sqlValue.integer(1n << 63n)).toThrow()
    expect(() => encodeChangeProgram({
      version: 3,
      steps: [{ sql: 'SELECT ?', bindings: [
        { parameter: { kind: 'index', index: 1 }, value: sqlValue.null() },
        { parameter: { kind: 'index', index: 1 }, value: sqlValue.null() },
      ] }],
    })).toThrow()
    expect(() => encodeChangeProgram({
      version: 3,
      steps: Array.from({ length: 257 }, () => sqlStatement('SELECT 1')),
    })).toThrow()
  })
})

describe('execution manifest', () => {
  it('round-trips and pins the engine digest, platform digest, profile pragma and limits', () => {
    const manifest = createExecutionManifest({
      profile: 'test', engineDigest: new Uint8Array(32).fill(7), platformDigest: new Uint8Array(32).fill(8), limits: { maxVmSteps: 42 },
    })
    const decoded = decodeExecutionManifest(encodeExecutionManifest(manifest))
    expect(decoded).toEqual(manifest)
    expect(decoded.limits.maxVmSteps).toBe(42)
    expect(decoded.programVersion).toBe(3)
    expect(decoded.recursiveTriggers).toBe(true)
    expect(() => createExecutionManifest({ profile: 'test', engineDigest: new Uint8Array(31), platformDigest: new Uint8Array(32) })).toThrow()
    expect(() => createExecutionManifest({ profile: 'test', engineDigest: new Uint8Array(32), platformDigest: new Uint8Array(31) })).toThrow()
  })
})
