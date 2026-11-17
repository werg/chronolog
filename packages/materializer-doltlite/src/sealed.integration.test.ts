import { generateX25519KeyPair, openSealedValue, sealSealedValue, type X25519KeyPair } from '@chronolog/crypto'
import {
  decodeSealedEnvelope, encodeSealedEnvelope, platformObjectId, platformOp, sealedOp, sqlStatement, utf8,
  type ProgramStep, type SealedEnvelope, type SealedRecipient,
} from '@chronolog/protocol'
import { afterEach, describe, expect, it } from 'vitest'

import type { DeterministicMaterializer } from './materializer.js'
import { MaterializerFixture, ROOT_KEY, replayProposal, rows, testKey } from './test-fixtures.js'
import type { ReplayProposal } from './types.js'

const fixtures = new MaterializerFixture()
const opened: DeterministicMaterializer[] = []
afterEach(async () => {
  for (const materializer of opened.splice(0)) materializer.close()
  await fixtures.cleanup()
})
const ALICE = testKey(0x10)
const BOB = testKey(0x20)
const CAROL = testKey(0x30)
const GROUP = testKey(1)

class SealedLedger {
  readonly transactions: ReplayProposal[] = []
  constructor(readonly materializer: DeterministicMaterializer) {}

  async submit(expected: string, actor: Uint8Array, ...steps: readonly (ProgramStep | string)[]): Promise<Uint8Array> {
    const clock = BigInt(this.transactions.length + 1)
    const transaction = await replayProposal(clock, `sealed-${clock}`, steps, this.materializer.executionManifestDigest, actor)
    this.transactions.push(transaction)
    await this.materializer.materialize(this.transactions)
    expect(this.materializer.outcome(transaction.txId)?.rejectionCode ?? 'accepted').toBe(expected)
    return transaction.txId
  }
}

async function setup(ownerInKey = false): Promise<{
  book: SealedLedger; bobKey: X25519KeyPair; carolKey: X25519KeyPair; row: readonly bigint[];
}> {
  const { materializer } = await fixtures.open()
  opened.push(materializer)
  const book = new SealedLedger(materializer)
  const [bobKey, carolKey] = await Promise.all([generateX25519KeyPair(), generateX25519KeyPair()])
  await book.submit('accepted', ROOT_KEY, ownerInKey
    ? `CREATE TABLE docs (id INTEGER NOT NULL, body BLOB, other BLOB, status TEXT,
        chronolog_owner INTEGER NOT NULL DEFAULT (chronolog_actor_id()), PRIMARY KEY (id, chronolog_owner)) STRICT`
    : 'CREATE TABLE docs (id INTEGER PRIMARY KEY, body BLOB, other BLOB, status TEXT) STRICT')
  await book.submit('accepted', ALICE, "INSERT INTO docs (id, status) VALUES (1, 'draft')")
  await book.submit('accepted', BOB, sealedOp.registerReaderKey(bobKey.publicKeyBytes))
  await book.submit('accepted', CAROL, sealedOp.registerReaderKey(carolKey.publicKeyBytes))
  const ownerId = BigInt(rows(materializer, 'SELECT chronolog_owner FROM docs')[0]![0] as string)
  return { book, bobKey, carolKey, row: ownerInKey ? [1n, ownerId] : [1n] }
}

async function policy(book: SealedLedger, row: readonly bigint[], readers: readonly Uint8Array[] = [BOB]): Promise<Uint8Array> {
  const txId = await book.submit('accepted', ALICE, sealedOp.readerPolicy({ table: 'docs', rowKey: row, expectedVersion: 0n, readers }))
  return platformObjectId(txId, 0)
}

async function encrypted(id: Uint8Array, recipients: readonly SealedRecipient[], options: {
  policyVersion?: bigint; dataVersion?: bigint; slot?: string; groupId?: Uint8Array; plaintext?: string;
} = {}): Promise<SealedEnvelope> {
  return sealSealedValue({
    context: { groupId: options.groupId ?? GROUP, policyId: id, policyVersion: options.policyVersion ?? 1n, slot: options.slot ?? 'body', dataVersion: options.dataVersion ?? 1n },
    plaintext: utf8(options.plaintext ?? 'private body'), recipients,
  })
}

function put(envelope: SealedEnvelope): ProgramStep {
  return sealedOp.put({ policyId: envelope.context.policyId, expectedPolicyVersion: envelope.context.policyVersion,
    expectedDataVersion: envelope.context.dataVersion - 1n, slot: envelope.context.slot, envelope })
}

describe('sealed columns and explicit reader policies', () => {
  it('keeps reader policies owner-controlled and applies column grants to sealed writes', async () => {
    const { book, bobKey, row } = await setup()
    const change = sealedOp.readerPolicy({ table: 'docs', rowKey: row, expectedVersion: 0n, readers: [BOB] })
    await book.submit('platform:not_owner', BOB, change)
    await book.submit('platform:not_owner', ROOT_KEY, change)
    await book.submit('platform:reader_key_missing', ALICE, sealedOp.readerPolicy({ table: 'docs', rowKey: row, expectedVersion: 0n, readers: [ALICE] }))
    const id = await policy(book, row)
    const value = await encrypted(id, [{ readerId: BOB, publicKey: bobKey.publicKeyBytes }])
    await book.submit('policy:docs:update', BOB, put(value))
    await book.submit('accepted', ALICE, platformOp.grant({ table: 'docs', rowKey: row, grantee: BOB, operations: ['update'], columns: ['status'] }))
    await book.submit('policy:docs:update', BOB, put(value))
    await book.submit('accepted', ALICE, platformOp.grant({ table: 'docs', rowKey: row, grantee: BOB, operations: ['update'], columns: ['body'] }))
    await book.submit('accepted', BOB, put(value))
    const stored = rows(book.materializer, 'SELECT body FROM docs')[0]![0] as Uint8Array
    expect(stored).toEqual(encodeSealedEnvelope(value))
    expect(await openSealedValue({ envelope: decodeSealedEnvelope(stored), expectedContext: value.context, readerId: BOB, recipientPrivateKey: bobKey.privateKey })).toEqual(utf8('private body'))
    expect(value.wraps.map((wrap) => wrap.readerId)).toEqual([BOB])
    await book.submit('policy:docs:update', ALICE, "UPDATE docs SET body = x'00'")
    await book.submit('accepted', ALICE, "UPDATE docs SET status = 'published'")
    expect(rows(book.materializer, 'SELECT count(*) FROM chronolog_sealed_write_exemptions')).toEqual([['0']])
  })

  it('checks policy/data versions, group binding, declared columns and exact recipients', async () => {
    const { book, bobKey, carolKey, row } = await setup()
    const id = await policy(book, row)
    const recipients = [{ readerId: BOB, publicKey: bobKey.publicKeyBytes }]
    await book.submit('platform:sealed_context_mismatch', ALICE, put(await encrypted(id, recipients, { groupId: testKey(9) })))
    for (const slot of ['BODY', 'status', 'id', 'missing']) {
      await book.submit('platform:sealed_column_invalid', ALICE, put(await encrypted(id, recipients, { slot })))
    }
    await book.submit('platform:sealed_readers_mismatch', ALICE, put(await encrypted(id, [{ readerId: BOB, publicKey: carolKey.publicKeyBytes }])))
    await book.submit('platform:sealed_readers_mismatch', ALICE, put(await encrypted(id, [...recipients, { readerId: CAROL, publicKey: carolKey.publicKeyBytes }])))
    const value = await encrypted(id, recipients)
    await book.submit('accepted', ALICE, put(value))
    await book.submit('platform:sealed_value_stale', ALICE, put(value))
    await book.submit('platform:reader_policy_stale', ALICE, sealedOp.readerPolicy({ table: 'docs', rowKey: row, expectedVersion: 0n, readers: [BOB] }))
    await book.submit('accepted', ALICE, sealedOp.readerPolicy({ table: 'docs', rowKey: row, expectedPolicyId: id, expectedVersion: 1n, readers: [] }))
    await book.submit('platform:reader_policy_stale', ALICE, put(await encrypted(id, recipients, { dataVersion: 2n })))
    await book.submit('platform:sealed_no_readers', ALICE, put(await encrypted(id, recipients, { policyVersion: 2n, dataVersion: 2n })))
  })

  it('snapshots registered keys and removes readers only from subsequent encrypted versions', async () => {
    const { book, bobKey, carolKey, row } = await setup()
    const id = await policy(book, row, [BOB, CAROL])
    const first = await encrypted(id, [{ readerId: BOB, publicKey: bobKey.publicKeyBytes }, { readerId: CAROL, publicKey: carolKey.publicKeyBytes }])
    await book.submit('accepted', ALICE, put(first))
    const rotated = await generateX25519KeyPair()
    await book.submit('accepted', CAROL, sealedOp.registerReaderKey(rotated.publicKeyBytes))
    // Registry rotation alone does not alter an already selected reader policy.
    const mismatch = await encrypted(id, [{ readerId: BOB, publicKey: bobKey.publicKeyBytes }, { readerId: CAROL, publicKey: rotated.publicKeyBytes }], { dataVersion: 2n })
    await book.submit('platform:sealed_readers_mismatch', ALICE, put(mismatch))
    await book.submit('accepted', ALICE, sealedOp.readerPolicy({ table: 'docs', rowKey: row, expectedPolicyId: id, expectedVersion: 1n, readers: [CAROL] }))
    const next = await encrypted(id, [{ readerId: CAROL, publicKey: rotated.publicKeyBytes }], { policyVersion: 2n, dataVersion: 2n, plaintext: 'after removal' })
    await book.submit('accepted', ALICE, put(next))
    expect(await openSealedValue({ envelope: first, expectedContext: first.context, readerId: BOB, recipientPrivateKey: bobKey.privateKey })).toEqual(utf8('private body'))
    await expect(openSealedValue({ envelope: next, expectedContext: next.context, readerId: BOB, recipientPrivateKey: bobKey.privateKey })).rejects.toBeDefined()
    expect(await openSealedValue({ envelope: next, expectedContext: next.context, readerId: CAROL, recipientPrivateKey: rotated.privateKey })).toEqual(utf8('after removal'))
  })

  it('versions separate sealed columns independently under the same reader policy', async () => {
    const { book, bobKey, row } = await setup()
    const id = await policy(book, row)
    const recipients = [{ readerId: BOB, publicKey: bobKey.publicKeyBytes }]
    await book.submit('accepted', ALICE,
      put(await encrypted(id, recipients)),
      put(await encrypted(id, recipients, { slot: 'other' })))
    await book.submit('accepted', ALICE, put(await encrypted(id, recipients, { dataVersion: 2n })))
    expect(rows(book.materializer, 'SELECT slot, data_version FROM chronolog_sealed_values ORDER BY slot')).toEqual([['body', '2'], ['other', '1']])
  })

  it('rolls back app-trigger mutations and never lends platform privileges to app triggers', async () => {
    const { book, bobKey, row } = await setup()
    const id = await policy(book, row)
    const value = await encrypted(id, [{ readerId: BOB, publicKey: bobKey.publicKeyBytes }])
    await book.submit('accepted', ROOT_KEY, `CREATE TRIGGER replace_after_sealing AFTER UPDATE OF body ON docs
      BEGIN DELETE FROM docs WHERE id = NEW.id; INSERT INTO docs (id) VALUES (NEW.id); END`)
    await book.submit('platform:sealed_write_changed', ALICE, put(value))
    expect(rows(book.materializer, 'SELECT body, status FROM docs')).toEqual([[null, 'draft']])
    expect(rows(book.materializer, 'SELECT closed_tx FROM chronolog_reader_policies')).toEqual([[null]])
    await book.submit('accepted', ROOT_KEY, 'DROP TRIGGER replace_after_sealing', `CREATE TRIGGER corrupt_policy AFTER UPDATE OF body ON docs
      BEGIN UPDATE chronolog_reader_policies SET version = version + 1; END`)
    await book.submit('denied', ALICE, put(value))
    expect(rows(book.materializer, 'SELECT count(*) FROM chronolog_sealed_write_exemptions')).toEqual([['0']])
    await book.submit('accepted', ROOT_KEY, 'DROP TRIGGER corrupt_policy', `CREATE TRIGGER guard_body BEFORE UPDATE OF body ON docs
      BEGIN SELECT chronolog_assert(NEW.status = 'ready', 'body_not_ready'); END`)
    await book.submit('assert:body_not_ready', ALICE, put(value))
    await book.submit('accepted', ALICE, "UPDATE docs SET status = 'ready'", put(value))
  })

  it.each(['delete', 'rekey', 'drop', 'rename_column'] as const)('closes a reader generation on %s and cannot revive it by reusing a row', async (operation) => {
    const { book, bobKey, row } = await setup()
    const id = await policy(book, row)
    const recipients = [{ readerId: BOB, publicKey: bobKey.publicKeyBytes }]
    await book.submit('accepted', ALICE, put(await encrypted(id, recipients)))
    if (operation === 'delete') await book.submit('accepted', ALICE, 'DELETE FROM docs', 'INSERT INTO docs (id) VALUES (1)')
    if (operation === 'rekey') await book.submit('accepted', ALICE, 'UPDATE docs SET id = 2', 'UPDATE docs SET id = 1')
    if (operation === 'drop') await book.submit('accepted', ROOT_KEY, 'DROP TABLE docs', 'CREATE TABLE docs (id INTEGER PRIMARY KEY, body BLOB) STRICT')
    if (operation === 'rename_column') await book.submit('accepted', ROOT_KEY, 'ALTER TABLE docs RENAME COLUMN body TO renamed', 'ALTER TABLE docs RENAME COLUMN renamed TO body')
    await book.submit('platform:reader_policy_closed', ALICE, put(await encrypted(id, recipients, { dataVersion: 2n })))
    expect(rows(book.materializer, 'SELECT closed_tx IS NOT NULL FROM chronolog_reader_policies')).toEqual([['1']])
    if (operation === 'delete') {
      const replacement = await policy(book, row)
      expect(replacement).not.toEqual(id)
      await book.submit('accepted', ALICE, put(await encrypted(replacement, recipients)))
    }
  })

  it.each([false, true])('preserves explicit readers across ownership transfer (owner in PK: %s)', async (ownerInKey) => {
    const { book, bobKey, row } = await setup(ownerInKey)
    const id = await policy(book, row)
    const value = await encrypted(id, [{ readerId: BOB, publicKey: bobKey.publicKeyBytes }])
    await book.submit('accepted', ALICE, put(value))
    const offerTx = await book.submit('accepted', ALICE, platformOp.transferRow({ table: 'docs', rowKey: row, toOwner: CAROL }))
    await book.submit('accepted', CAROL, platformOp.acceptTransfer(await platformObjectId(offerTx, 0)))
    expect(rows(book.materializer, 'SELECT closed_tx FROM chronolog_reader_policies')).toEqual([[null]])
    const ownerId = BigInt(rows(book.materializer, 'SELECT chronolog_owner FROM docs')[0]![0] as string)
    const nextRow = ownerInKey ? [1n, ownerId] : row
    const change = sealedOp.readerPolicy({ table: 'docs', rowKey: nextRow, expectedPolicyId: id, expectedVersion: 1n, readers: [CAROL] })
    await book.submit('platform:not_owner', ALICE, change)
    // Transfer does not make the new owner a reader of the old ciphertext.
    expect(value.wraps.map((wrap) => wrap.readerId)).toEqual([BOB])
    await book.submit('accepted', CAROL, change)
  })

  it('preserves table rename bindings, binds transfer offers to policy state, and replays identically', async () => {
    const { book, bobKey, row } = await setup()
    const id = await policy(book, row)
    const value = await encrypted(id, [{ readerId: BOB, publicKey: bobKey.publicKeyBytes }])
    await book.submit('accepted', ALICE, put(value))
    const offerTx = await book.submit('accepted', ALICE, platformOp.transferRow({ table: 'docs', rowKey: row, toOwner: CAROL }))
    await book.submit('accepted', ALICE, sealedOp.readerPolicy({ table: 'docs', rowKey: row, expectedPolicyId: id, expectedVersion: 1n, readers: [BOB] }))
    await book.submit('platform:offer_stale', CAROL, platformOp.acceptTransfer(await platformObjectId(offerTx, 0)))
    await book.submit('accepted', ROOT_KEY, 'ALTER TABLE docs RENAME TO renamed_docs')
    await book.submit('accepted', ALICE, put(await encrypted(id, [{ readerId: BOB, publicKey: bobKey.publicKeyBytes }], { policyVersion: 2n, dataVersion: 2n })))
    expect(rows(book.materializer, 'SELECT tbl FROM chronolog_reader_policies')).toEqual([['renamed_docs']])
    const { materializer: replay } = await fixtures.open()
    opened.push(replay)
    await replay.materialize(book.transactions)
    for (const table of ['renamed_docs', 'chronolog_reader_policies', 'chronolog_policy_readers', 'chronolog_sealed_values']) {
      expect(rows(replay, `SELECT * FROM ${table}`)).toEqual(rows(book.materializer, `SELECT * FROM ${table}`))
    }
    await book.submit('denied', ALICE, sqlStatement('UPDATE chronolog_sealed_values SET envelope = ?', [new Uint8Array()]))
  })
})
