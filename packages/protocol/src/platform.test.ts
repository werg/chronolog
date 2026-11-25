import { describe, expect, it } from 'vitest'

import {
  GROUP_COLLECTIVE_ID,
  decodeChangeProgram,
  encodeCanonicalCbor,
  encodeChangeProgram,
  isPlatformOp,
  isSqlStatementStep,
  platformObjectId,
  platformOp,
  platformOpFromCanonicalCbor,
  platformOpToCanonicalCbor,
  program,
  sqlValue,
  type PlatformOp,
  type CborValue,
} from './index.js'

const key = (fill: number): Uint8Array => new Uint8Array(32).fill(fill)

const everyOperation: readonly PlatformOp[] = [
  platformOp.grant({ table: 'notes', grantee: key(2), operations: ['insert', 'update', 'delete'] }),
  platformOp.grant({ table: 'notes', grantee: key(2), grantor: key(4), operations: ['update'], rowKey: [1n, sqlValue.real(2), 'x', new Uint8Array([1])], columns: ['body', 'title'] }),
  platformOp.revokeGrant(key(3)),
  platformOp.createCollective({ governance: { insert: 'member', update: 'admin', delete: 'admin' }, invitees: [key(5), key(6)] }),
  platformOp.createCollective({ governance: { insert: 'admin', update: 'admin', delete: 'admin' } }),
  platformOp.acceptMembership(key(7)),
  platformOp.leave(key(7)),
  platformOp.setMembers(GROUP_COLLECTIVE_ID, [{ member: key(8), role: 'member' }, { member: key(9), role: 'admin' }, { member: key(10), role: 'remove' }]),
  platformOp.transferRow({ table: 'notes', rowKey: [1n], toOwner: key(11) }),
  platformOp.transferRow({ table: 'notes', rowKey: [1n], toOwner: key(11), fromOwner: key(12), carry: true }),
  platformOp.transferAll({ toOwner: key(13) }),
  platformOp.acceptTransfer(key(14)),
  platformOp.cancelTransfer(key(14)),
  platformOp.seedRows('notes', ['id', 'chronolog_owner'], [[1n, key(1)], [2n, key(2)]]),
  platformOp.endSeeding(),
  platformOp.grantDdl({ scope: { kind: 'namespace', name: 'main' }, grantee: key(2), operations: ['create'] }),
  platformOp.grantDdl({ scope: { kind: 'object', name: 'notes' }, grantee: key(2), operations: ['alter', 'drop', 'index', 'trigger'] }),
  platformOp.revokeDdl(key(3)),
]

describe('platform operations', () => {
  it('round-trip every operation through canonical CBOR', () => {
    for (const op of everyOperation) {
      const encoded = encodeCanonicalCbor(platformOpToCanonicalCbor(op))
      const decoded = platformOpFromCanonicalCbor(platformOpToCanonicalCbor(op))
      expect(decoded).toEqual(op)
      expect(encodeCanonicalCbor(platformOpToCanonicalCbor(decoded))).toEqual(encoded)
      expect(isPlatformOp(op)).toBe(true)
    }
  })

  it('mixes SQL statements and platform operations in one program', () => {
    const change = program('CREATE TABLE notes (id INTEGER PRIMARY KEY, body TEXT)')
    const decoded = decodeChangeProgram(encodeChangeProgram(change))
    expect(decoded).toEqual(change)
    expect(decoded.steps.map(isSqlStatementStep)).toEqual([true])
  })

  it('rejects malformed operations', () => {
    expect(() => platformOp.grant({ table: '', grantee: key(1), operations: ['update'] })).toThrow()
    expect(() => platformOp.grant({ table: 'x'.repeat(129), grantee: key(1), operations: ['update'] })).toThrow()
    expect(() => platformOp.grant({ table: 't', grantee: key(1), operations: [] })).toThrow()
    expect(() => platformOp.grant({ table: 't', grantee: key(1), operations: ['update', 'update'] })).toThrow()
    expect(() => platformOp.grant({ table: 't', grantee: key(1), operations: ['delete', 'update'] })).toThrow()
    expect(() => platformOp.grant({ table: 't', grantee: new Uint8Array(31), operations: ['update'] })).toThrow()
    expect(() => platformOp.grant({ table: 't', grantee: key(1), operations: ['update'], columns: [] })).toThrow()
    expect(() => platformOp.grant({ table: 't', grantee: key(1), operations: ['update'], rowKey: [] })).toThrow()
    expect(() => platformOp.createCollective({ governance: { insert: 'member', update: 'member', delete: 'member' }, invitees: [key(1), key(1)] })).toThrow()
    expect(() => platformOp.setMembers(key(1), [])).toThrow()
    expect(() => platformOp.seedRows('t', ['a', 'A'], [[1n, 2n]])).toThrow()
    expect(() => platformOp.seedRows('t', ['a'], [[1n, 2n]])).toThrow()
    expect(() => platformOp.seedRows('t', ['a'], [])).toThrow()
    // A transfer of every row always carries dependents.
    expect(() => platformOpToCanonicalCbor({ op: 'transfer_offer', scope: { kind: 'all' }, toOwner: key(1), carry: false })).toThrow()
  })

  it('encodes scoped DDL operations as ordinary program steps with fixed codes', () => {
    const grant = platformOp.grantDdl({ scope: { kind: 'object', name: 'notes' }, grantee: key(2), operations: ['alter', 'trigger'] })
    expect(platformOpToCanonicalCbor(grant)).toEqual(new Map<bigint, CborValue>([[0n, 11n], [1n, [1n, 'notes']], [2n, key(2)], [3n, [1n, 4n]]]))
    expect(platformOpToCanonicalCbor(platformOp.revokeDdl(key(3)))).toEqual(new Map<bigint, CborValue>([[0n, 12n], [1n, key(3)]]))
    const mixed = program('CREATE TABLE notes (id INTEGER PRIMARY KEY)', grant, 'ALTER TABLE notes ADD COLUMN value TEXT', platformOp.revokeDdl(key(3)))
    expect(decodeChangeProgram(encodeChangeProgram(mixed))).toEqual(mixed)
    for (const scope of [{ kind: 'namespace', name: 'other' }, { kind: 'namespace', name: 'main' }, { kind: 'object', name: 'notes' }] as const) {
      const operations = scope.kind === 'object' ? ['create'] as const : ['drop'] as const
      expect(() => platformOp.grantDdl({ scope, grantee: key(2), operations })).toThrow()
    }
    for (const operations of [[], ['drop', 'alter'], ['alter', 'alter']] as const) {
      expect(() => platformOp.grantDdl({ scope: { kind: 'object', name: 'notes' }, grantee: key(2), operations })).toThrow()
    }
    expect(() => platformOpFromCanonicalCbor(new Map<bigint, CborValue>([[0n, 11n], [1n, [2n, 'notes']], [2n, key(2)], [3n, [1n]]]))).toThrow()
    expect(() => platformOpFromCanonicalCbor(new Map<bigint, CborValue>([[0n, 12n], [1n, key(3)], [2n, 0n]]))).toThrow()
  })

  it('derives platform object ids from the transaction and step', async () => {
    const first = await platformObjectId(key(1), 0)
    expect(first).toHaveLength(32)
    expect(await platformObjectId(key(1), 0)).toEqual(first)
    expect(await platformObjectId(key(1), 1)).not.toEqual(first)
    expect(await platformObjectId(key(2), 0)).not.toEqual(first)
  })
})
