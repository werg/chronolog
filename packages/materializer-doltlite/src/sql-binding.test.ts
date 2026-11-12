import { DatabaseSync } from '@dolthub/doltlite'
import { numberToSqlRealBinding } from '@chronolog/protocol'
import { describe, expect, it } from 'vitest'

import { executeSqlObservation } from './sql-executor.js'
import { assertNativeSecurityConfiguration, configureSqliteLimits } from './sql-profile.js'
import type { DatabaseLike } from './types.js'

describe('consensus parameter binding', () => {
  it('binds integral REAL values as REAL and empty BLOBs as BLOB', () => {
    const db = new DatabaseSync(':memory:') as unknown as DatabaseLike
    assertNativeSecurityConfiguration(db.configureSecurity())
    configureSqliteLimits(db)
    const result = executeSqlObservation(db, {
      sql: 'SELECT typeof(?1), typeof(?2), typeof(?3), length(?3)',
      bindings: [
        { parameter: { kind: 'index', index: 1 }, value: numberToSqlRealBinding(1) },
        { parameter: { kind: 'index', index: 2 }, value: numberToSqlRealBinding(-0) },
        { parameter: { kind: 'index', index: 3 }, value: { kind: 'blob', bytes: new Uint8Array(0) } },
      ],
    }, 'multiset', 10, 1 << 20)
    const texts = result.rows[0]!.slice(0, 3).map((value) => value.kind === 'text' ? new TextDecoder().decode(value.utf8) : value.kind)
    expect(texts).toEqual(['real', 'real', 'blob'])
    expect(result.rows[0]![3]).toEqual({ kind: 'integer', value: 0n })
  })
})
