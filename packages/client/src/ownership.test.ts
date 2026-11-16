import { platformObjectId } from '@chronolog/protocol'
import { describe, expect, it } from 'vitest'

import { TransactionRejectedError, createdObjectId, ownerKeySql, ownershipSteps, parseRejectionCode } from './ownership.js'

describe('parseRejectionCode', () => {
  it('parses policy, platform, assert, schema and engine codes', () => {
    expect(parseRejectionCode('policy:notes:update')).toEqual({ kind: 'policy', table: 'notes', operation: 'update' })
    // Table names may contain ':'; the operation is after the last one.
    expect(parseRejectionCode('policy:a:b:delete')).toEqual({ kind: 'policy', table: 'a:b', operation: 'delete' })
    expect(parseRejectionCode('platform:offer_closed')).toEqual({ kind: 'platform', reason: 'offer_closed' })
    expect(parseRejectionCode('assert:balance_changed')).toEqual({ kind: 'assert', code: 'balance_changed' })
    expect(parseRejectionCode('schema_unregistered')).toEqual({ kind: 'schema', code: 'schema_unregistered' })
    expect(parseRejectionCode('trigger_ignore')).toEqual({ kind: 'schema', code: 'trigger_ignore' })
    expect(parseRejectionCode('constraint')).toEqual({ kind: 'engine', code: 'constraint' })
    expect(parseRejectionCode('policy:notes:frobnicate')).toEqual({ kind: 'engine', code: 'policy:notes:frobnicate' })
  })

  it('carries the parsed reason and failing step on TransactionRejectedError', () => {
    const error = new TransactionRejectedError('tx-1', { code: 'policy:notes:insert', statementIndex: 2 })
    expect(error.reason).toEqual({ kind: 'policy', table: 'notes', operation: 'insert' })
    expect(error.stepIndex).toBe(2)
    expect(error.message).toContain('policy:notes:insert')
  })
})

describe('ownership helpers', () => {
  it('derives created ids from the transaction id text and step index', async () => {
    expect(await createdObjectId('tx-abc', 3)).toEqual(await platformObjectId(new TextEncoder().encode('tx-abc'), 3))
  })

  it('builds owner SQL and normalizes grant operation order', () => {
    expect(ownerKeySql('n')).toBe('(SELECT key FROM chronolog_principals WHERE id = n.chronolog_owner)')
    expect(ownerKeySql()).toBe('(SELECT key FROM chronolog_principals WHERE id = chronolog_owner)')
    const grant = ownershipSteps.share({ table: 't', with: new Uint8Array(32).fill(1), operations: ['delete', 'update'] })
    expect(grant.op === 'grant' ? grant.operations : []).toEqual(['update', 'delete'])
    const cancel = ownershipSteps.cancelOffer(new Uint8Array(32).fill(2))
    expect(cancel.op).toBe('transfer_cancel')
    const team = ownershipSteps.createTeam()
    expect(team.op === 'create_collective' ? team.governance : null).toEqual({ insert: 'member', update: 'member', delete: 'admin' })
  })
})
