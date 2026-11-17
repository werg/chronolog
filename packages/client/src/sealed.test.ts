import { execFile } from 'node:child_process'
import { fileURLToPath } from 'node:url'
import { promisify } from 'node:util'

import * as sealedCrypto from '@chronolog/crypto'
import { generateX25519KeyPair } from '@chronolog/crypto'
import { encodeSealedEnvelope, utf8, type SealedEnvelope, type SealedPlatformOp } from '@chronolog/protocol'
import type { SettlementEvidence } from '@chronolog/rpc'
import { afterEach, describe, expect, it, vi } from 'vitest'

import type { LocalSqlQueryResponse, TransactionHandle, TransactionStepInput } from './client.js'
import type { DecodedLocalSqlValue } from './local-sql.js'
import { SealedDataActions, SealedPolicyNotFinalError, SealedVersionConflictError } from './sealed.js'

const bytes = (seed: number): Uint8Array => new Uint8Array(32).fill(seed)
const GROUP = Buffer.from(bytes(1)).toString('base64url')
const execFileAsync = promisify(execFile)

afterEach(() => { vi.restoreAllMocks() })

function result(rows: readonly (readonly DecodedLocalSqlValue[])[]): LocalSqlQueryResponse {
  return {
    revision: { groupId: GROUP, materializedRevision: '7', eventSetRevision: '9', publishedOrderLength: '3', executionManifestDigest: '', replaying: false, view: 'local', finalRevision: '7', finalOrderLength: '3' },
    result: { columns: [], rows, truncated: false, consensusSafe: false, raw: { columns: [], rows: [], truncated: false, consensusSafe: false } },
  }
}

function fixture(publicKey: Uint8Array) {
  const state = {
    policyVersion: 1n,
    policyClosed: false,
    confidence: 'policy_watermark_reached' as SettlementEvidence['confidence'],
    final: true,
    unresolvedReferences: [] as SettlementEvidence['unresolvedReferences'],
    accepted: true,
    envelope: undefined as SealedEnvelope | undefined,
  }
  const handle = { createdId: async () => bytes(2) } as unknown as TransactionHandle
  const client = {
    groupId: GROUP,
    identity: vi.fn(async () => bytes(4)),
    query: vi.fn(async (sql: string, _parameters?: readonly unknown[], _options?: unknown): Promise<LocalSqlQueryResponse> => {
      if (sql.includes('FROM chronolog_tables')) return result([['odd"notes', 'id'], ['odd"notes', 'chronolog_owner']])
      if (sql.includes('FROM chronolog_reader_policies')) return result([
        [bytes(2), 'notes', 'rk1:opaque', state.policyVersion, utf8('policy-tx-id'), state.policyClosed ? utf8('closed-tx') : null, bytes(4), publicKey],
      ])
      if (sql.includes('FROM chronolog_sealed_values')) return result(state.envelope === undefined ? [] : [
        [state.envelope.context.dataVersion, state.envelope.context.policyVersion, encodeSealedEnvelope(state.envelope), utf8('value-tx-id')],
      ])
      throw new Error(`Unexpected query ${sql}`)
    }),
    transaction: vi.fn(async (_steps: readonly TransactionStepInput[]) => handle),
    getSettlementEvidence: vi.fn(async (transactionId: string): Promise<SettlementEvidence> => ({
      transactionId, confidence: state.confidence, unresolvedReferences: state.unresolvedReferences,
      outcome: { final: state.final, outcome: { type: state.accepted ? 'accepted' : 'pending' } },
    }) as SettlementEvidence),
  }
  return { client, state, actions: new SealedDataActions(client), handle }
}

describe('sealed client helpers', () => {
  it('preserves caller-owned Buffer plaintext when policy preflight rejects', async () => {
    const { actions, state } = fixture(bytes(8))
    state.confidence = 'provisional'
    state.final = false
    const plaintext = Buffer.from('the caller still owns these bytes')
    const expected = Uint8Array.from(plaintext)
    await expect(actions.put(bytes(2), 'body', plaintext)).rejects.toBeInstanceOf(SealedPolicyNotFinalError)
    expect(Uint8Array.from(plaintext)).toEqual(expected)
  })

  it('copies Buffer plaintext and policy ids before awaiting preflight without clearing caller memory', async () => {
    const reader = await generateX25519KeyPair()
    const { actions, client } = fixture(reader.publicKeyBytes)
    const plaintext = Buffer.from('the selected view only')
    const expected = Uint8Array.from(plaintext)
    const policyId = Buffer.from(bytes(2))
    const pending = actions.put(policyId, 'body', plaintext)
    // put() has started its asynchronous policy query. Later caller changes
    // must not change the chosen policy or the bytes that will be encrypted.
    plaintext.fill(0xa5)
    policyId.fill(0xa6)
    const change = await pending
    const step = client.transaction.mock.calls[0]![0][0] as SealedPlatformOp
    if (step.op !== 'sealed_put') throw new Error('Expected sealed put')
    expect(step.envelope.ciphertext.byteLength).toBe(expected.byteLength + 16)
    expect(await sealedCrypto.openSealedValue({ envelope: step.envelope, expectedContext: change.context, readerId: bytes(4), recipientPrivateKey: reader.privateKey })).toEqual(expected)
    expect(plaintext.every((byte) => byte === 0xa5)).toBe(true)
    expect(policyId.every((byte) => byte === 0xa6)).toBe(true)
  })

  it('encrypts and decrypts using browser globals without Node Buffer', async () => {
    // Vitest's concurrent IPC also uses Buffer. Remove it only in an isolated
    // process, where the real client and crypto calls run without the runner.
    const { stdout } = await execFileAsync(process.execPath, ['--import', 'tsx',
      fileURLToPath(new URL('../../../test/fixtures/sealed-browser-globals.ts', import.meta.url)),
    ], { timeout: 20_000 })
    expect(stdout.trim()).toBe('sealed-browser-globals-ok')
  })

  it('submits explicit key registration and versioned reader policy changes', async () => {
    const reader = await generateX25519KeyPair()
    const { actions, client, handle } = fixture(reader.publicKeyBytes)
    expect(await actions.registerKey(reader.publicKeyBytes)).toBe(handle)
    expect(client.transaction.mock.calls[0]![0][0]).toEqual({ op: 'register_reader_key', publicKey: reader.publicKeyBytes })
    const created = await actions.setReaders({ table: 'notes', row: [1n], readers: [bytes(4)], expectedVersion: 0n })
    expect(created).toEqual({ handle, id: bytes(2) })
    const replaced = await actions.setReaders({ table: 'notes', row: [1n], readers: [], expectedVersion: 1n, expectedPolicyId: bytes(2) })
    expect(replaced.id).toEqual(bytes(2))
    expect(client.transaction.mock.calls[2]![0][0]).toMatchObject({ op: 'reader_policy', readers: [], expectedVersion: 1n, expectedPolicyId: bytes(2) })
  })

  it('resolves the stored typed row key and pins metadata/query reads to one materialized revision', async () => {
    const { actions, client } = fixture(bytes(8))
    const policy = await actions.getPolicy('odd"notes', [10n, 1n])
    expect(policy?.updatedTransactionId).toBe('policy-tx-id')
    expect(policy?.policyId).toEqual(bytes(2))
    const query = client.query.mock.calls[1]!
    expect(query[0]).toContain('FROM "odd""notes" AS t')
    expect(query[0]).toContain('chronolog_row_key(t."id", (SELECT key FROM chronolog_principals')
    expect(query[0]).toContain('p.closed_tx IS NULL')
    expect(query[1]).toEqual(['odd"notes', 10n, 1n])
    expect(query[2]).toEqual({ atRevision: '7' })
    await expect(actions.getPolicy('notes', [10n])).rejects.toThrow('primary-key')
  })

  it('refuses unfinalized policies before encryption or publication, including unresolved evidence', async () => {
    const reader = await generateX25519KeyPair()
    const { actions, state, client } = fixture(reader.publicKeyBytes)
    const seal = vi.spyOn(sealedCrypto, 'sealSealedValue')
    // A watermark observation alone is insufficient until its result is applied.
    state.final = false
    await expect(actions.put(bytes(2), 'body', utf8('never encrypt yet'))).rejects.toBeInstanceOf(SealedPolicyNotFinalError)
    state.final = true
    state.unresolvedReferences = [{ kind: 'attestation', reference: 'missing' }]
    await expect(actions.put(bytes(2), 'body', utf8('still unresolved'))).rejects.toMatchObject({ code: 'SEALED_POLICY_NOT_FINAL' })
    state.unresolvedReferences = []
    state.accepted = false
    await expect(actions.put(bytes(2), 'body', utf8('not accepted'))).rejects.toMatchObject({ code: 'SEALED_POLICY_NOT_FINAL' })
    expect(seal).not.toHaveBeenCalled()
    expect(client.transaction).not.toHaveBeenCalled()
    expect(client.getSettlementEvidence).toHaveBeenCalledWith('policy-tx-id')
  })

  it('uses immutable acceptance rather than requiring a peer-policy watermark from the selected provider', async () => {
    const reader = await generateX25519KeyPair()
    const { actions, state, client } = fixture(reader.publicKeyBytes)
    state.confidence = 'insufficient'
    state.final = true
    const change = await actions.put(bytes(2), 'body', utf8('final coordinated policy'))
    expect(change.context.policyVersion).toBe(1n)
    expect(client.transaction).toHaveBeenCalledOnce()
  })

  it('encrypts only the explicit reader snapshot, with an explicit provisional override for development', async () => {
    const reader = await generateX25519KeyPair()
    const { actions, state, client } = fixture(reader.publicKeyBytes)
    state.confidence = 'provisional'
    state.final = false
    const change = await actions.put(bytes(2), 'body', utf8('secret'), { allowProvisionalPolicy: true })
    expect(client.getSettlementEvidence).not.toHaveBeenCalled()
    expect(change.context).toEqual({ groupId: bytes(1), policyId: bytes(2), policyVersion: 1n, slot: 'body', dataVersion: 1n })
    const step = client.transaction.mock.calls[0]![0][0] as SealedPlatformOp
    expect(step.op).toBe('sealed_put')
    if (step.op !== 'sealed_put') throw new Error('Expected sealed put')
    expect(step.expectedDataVersion).toBe(0n)
    expect(step.envelope.wraps.map((wrap) => wrap.readerId)).toEqual([bytes(4)])
    expect(await sealedCrypto.openSealedValue({ envelope: step.envelope, expectedContext: change.context, readerId: bytes(4), recipientPrivateKey: reader.privateKey })).toEqual(utf8('secret'))
  })

  it('checks expected versions before encryption and reads old values under their original policy version', async () => {
    const reader = await generateX25519KeyPair()
    const { actions, state, client } = fixture(reader.publicKeyBytes)
    state.envelope = await sealedCrypto.sealSealedValue({
      context: { groupId: bytes(1), policyId: bytes(2), policyVersion: 1n, slot: 'body', dataVersion: 3n },
      plaintext: utf8('old secret'), recipients: [{ readerId: bytes(4), publicKey: reader.publicKeyBytes }],
    })
    state.policyVersion = 2n
    const seal = vi.spyOn(sealedCrypto, 'sealSealedValue')
    await expect(actions.put(bytes(2), 'body', utf8('new'), { expectedPolicyVersion: 1n })).rejects.toBeInstanceOf(SealedVersionConflictError)
    await expect(actions.put(bytes(2), 'body', utf8('new'), { expectedDataVersion: 2n })).rejects.toMatchObject({ versionKind: 'data', actual: 3n })
    expect(seal).not.toHaveBeenCalled()
    const stored = await actions.get(bytes(2), 'body')
    expect(stored?.policyVersion).toBe(1n)
    expect(await actions.decrypt(stored!, reader.privateKey)).toEqual(utf8('old secret'))
    const change = await actions.put(bytes(2), 'body', utf8('new'), { expectedPolicyVersion: 2n, expectedDataVersion: 3n })
    expect(change.context).toMatchObject({ policyVersion: 2n, dataVersion: 4n })
    expect(client.getSettlementEvidence).toHaveBeenCalledWith('policy-tx-id')
  })

  it('binds reads/decryption to the configured group and requested policy/column, not ciphertext claims', async () => {
    const reader = await generateX25519KeyPair()
    const { actions, state } = fixture(reader.publicKeyBytes)
    state.envelope = await sealedCrypto.sealSealedValue({
      context: { groupId: bytes(1), policyId: bytes(2), policyVersion: 1n, slot: 'body', dataVersion: 1n },
      plaintext: utf8('secret'), recipients: [{ readerId: bytes(4), publicKey: reader.publicKeyBytes }],
    })
    await expect(actions.get(bytes(3), 'body')).rejects.toThrow('CONTEXT_MISMATCH')
    await expect(actions.get(bytes(2), 'other')).rejects.toThrow('CONTEXT_MISMATCH')
    const stored = await actions.get(bytes(2), 'body')
    await expect(actions.decrypt(stored!, reader.privateKey, bytes(4), { ...state.envelope.context, dataVersion: 2n })).rejects.toThrow('CONTEXT_MISMATCH')
    state.envelope = { ...state.envelope, context: { ...state.envelope.context, groupId: bytes(8) } }
    await expect(actions.get(bytes(2), 'body')).rejects.toThrow('CONTEXT_MISMATCH')
  })
})
