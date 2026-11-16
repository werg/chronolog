import { mkdtemp, open, readFile, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { TransactionRejectedError, type ChronologClient } from '@chronolog/client'
import { createDoltLiteExecutionManifest, createDoltLiteMaterializationRuntime, DeterministicMaterializer } from '@chronolog/materializer-doltlite'
import { bytesToHex, type EventPayload } from '@chronolog/protocol'
import type { AgentClient } from '@tendriller/core'
import type { BlobUploadCompletion } from '@tendriller/core/contract'
import { afterEach, describe, expect, it } from 'vitest'

import { createBlobMetadataRecipe, type FileUploadIntent, type StagedFileReference } from '../examples/blob-metadata.js'
import { createNativeBrowserFixture } from '../tools/browser-event-fixture.js'

const cleanup: Array<() => void | Promise<void>> = []
afterEach(async () => { for (const close of cleanup.splice(0).reverse()) await close() })
const input = (operationId: string, expectedRevision: string | null = null): FileUploadIntent => ({
  operationId, expectedRevision, path: 'documents/report.txt', mediaType: 'text/plain', kind: 'file',
})
const bytes = (text: string) => new TextEncoder().encode(text)
const deadline = () => ({ signal: AbortSignal.timeout(15_000) })

async function fixture() {
  const directory = await mkdtemp(join(tmpdir(), 'chronolog-native-blob-metadata-'))
  cleanup.push(() => rm(directory, { recursive: true, force: true }))
  const native = await createNativeBrowserFixture({ directory, browsers: [], manifest: createDoltLiteExecutionManifest(),
    materialization: async ({ identity, executionManifest }) => createDoltLiteMaterializationRuntime(await DeterministicMaterializer.open({
      path: join(directory, 'application.db'), executionManifest, rootAdministrator: identity.signing.publicKeyBytes, checkpointEvery: 1,
    })) })
  cleanup.push(() => native.close())
  const calls: { cid: string; bytes: Uint8Array }[] = []
  const behavior = { unavailable: false, loseUploadReply: false, incorrectDigest: false, pinned: true, loseMetadataReply: false }
  // Real bytes are written outside SQL. This contract fixture represents one
  // host location, not a deployed Tendriller service or an independent backup.
  const uploads: Pick<AgentClient['blobs'], 'upload'> = {
    async upload(data, options = {}): Promise<BlobUploadCompletion> {
      if (!(data instanceof Uint8Array) || options.cid === undefined) throw new Error('TEST_UPLOAD_REQUIRES_BYTES_AND_CID')
      calls.push({ cid: options.cid, bytes: data.slice() })
      if (behavior.unavailable) throw new Error('upload host unavailable')
      const sha256 = bytesToHex(new Uint8Array(await crypto.subtle.digest('SHA-256', new Uint8Array(data))))
      const path = join(directory, `${sha256}.blob`)
      try {
        const file = await open(path, 'wx')
        try { await file.writeFile(data); await file.sync() } finally { await file.close() }
      } catch (error) {
        if (!(error instanceof Error) || !('code' in error) || error.code !== 'EEXIST') throw error
        expect(new Uint8Array(await readFile(path))).toEqual(data)
      }
      if (behavior.loseUploadReply) { behavior.loseUploadReply = false; throw new Error('upload reply lost') }
      const id = `b_${[...sha256.slice(0, 20)].map(char => 'abcdefghijklmnop'[parseInt(char, 16)]).join('')}`
      return { status: 'completed', blob: { id, sha256: behavior.incorrectDigest ? '0'.repeat(64) : sha256, size: data.length,
        type: options.type ?? 'application/octet-stream', url: `https://host.example.test/blobs/${id}`, created_at: 1000,
        retention: { expires_at: behavior.pinned ? null : 5000, reasons: behavior.pinned ? ['pinned'] : ['upload'] } } }
    },
  }
  const client: Pick<ChronologClient, 'groupId' | 'submit'> = {
    groupId: native.client.groupId,
    async submit(change, options) {
      const result = await native.client.submit(change, options)
      if (behavior.loseMetadataReply) {
        behavior.loseMetadataReply = false
        try { await result.final(deadline()) } finally { result.dispose() }
        throw new Error('metadata reply lost')
      }
      return result
    },
  }
  const options = { client, uploads, store: native.store, historyId: 'native-fixture/history', locationId: 'test-local-upload',
    retentionPolicy: 'require-pin' as const, now: () => 2000 }
  const recipe = createBlobMetadataRecipe(options)
  await recipe.initialize({ operationId: 'blob-schema', ...deadline() })
  return { native, calls, behavior, recipe, options,
    readBytes: async (digest: string) => new Uint8Array(await readFile(join(directory, `${digest}.blob`))),
    events: async () => (await native.node.events.read({ topics: ['files'] })).transactions.flatMap(transaction => transaction.events),
    head: async () => (await native.client.query('SELECT f.path, f.revision, v.sha256, v.size, v.kind FROM blob_files AS f JOIN blob_file_versions AS v ON v.revision = f.revision')).result.rows,
  }
}

describe('application blob metadata with native SQL and authority', () => {
  it('stages exact immutable bytes before metadata, recovers a lost final reply, and uses the same reference flow for captures', async () => {
    const f = await fixture(), body = bytes('immutable report body'), request = input('file-1')
    const pending = f.recipe.stage(body, request, deadline())
    body.fill(0)
    const staged = await pending
    expect(staged).toMatchObject({ revision: 'file-1', path: 'documents/report.txt', previousRevision: null, kind: 'file',
      availability: { locationId: 'test-local-upload', observedAtMs: 2000, additionalDurableCopies: 'unknown',
        receipt: { status: 'completed', blob: { retention: { expires_at: null, reasons: ['pinned'] } } } }, orphanPolicy: 'retain-under-host-policy' })
    expect(await f.readBytes(staged.sha256)).toEqual(bytes('immutable report body'))
    expect(await f.head()).toEqual([])
    expect(await f.events()).toEqual([])
    f.behavior.loseMetadataReply = true
    await expect(f.recipe.commit('file-1', deadline())).rejects.toThrow('metadata reply lost')
    const original = (await f.native.client.operations.get('file-1'))!.proposalId
    const restarted = createBlobMetadataRecipe({ ...f.options, now: () => 9000 })
    expect(await restarted.commit('file-1', deadline())).toBe(original)
    expect(await restarted.stage(bytes('immutable report body'), request, deadline())).toEqual(staged)
    expect(f.calls).toHaveLength(1)
    expect(await f.head()).toEqual([['documents/report.txt', 'file-1', staged.sha256, BigInt(staged.size), 'file']])
    expect(await f.events()).toHaveLength(1)
    await expect(restarted.stage(bytes('different bytes'), request, deadline())).rejects.toThrow('BLOB_OPERATION_ID_CONFLICT')
    const capture = await restarted.stage(bytes('camera output'), { ...input('capture-1'), path: 'captures/photo.bin', mediaType: 'application/octet-stream', kind: 'capture' }, deadline())
    await restarted.commit('capture-1', deadline())
    const event = (await f.events()).at(-1)!
    expect(event.payload).toEqual({ type: 'file.committed', version: 1, reference: capture })
    expect(JSON.stringify(event.payload)).not.toContain('camera output')
    expect((await f.native.client.query('SELECT count(*) FROM blob_file_versions')).result.rows).toEqual([[2n]])
    f.native.assertHealthy()
  })

  it('atomically rejects a stale filename revision without an effective event and preserves the rejected upload for review', async () => {
    const f = await fixture()
    await f.recipe.stage(bytes('original'), input('file-0'), deadline())
    const original = await f.recipe.commit('file-0', deadline())
    const stale = await f.recipe.stage(bytes('stale edit'), input('file-stale', 'file-0'), deadline())
    const current = await f.recipe.stage(bytes('winning edit'), input('file-current', 'file-0'), deadline())
    await f.recipe.commit('file-current', deadline())
    await expect(f.recipe.commit('file-stale', deadline())).rejects.toMatchObject({ code: 'assert:file_revision_changed', reason: { kind: 'assert', code: 'file_revision_changed' } })
    await expect(f.recipe.commit('file-stale', deadline())).rejects.toBeInstanceOf(TransactionRejectedError)
    expect(await f.recipe.commit('file-0', deadline())).toBe(original)
    expect(await f.head()).toEqual([['documents/report.txt', 'file-current', current.sha256, BigInt(current.size), 'file']])
    expect((await f.native.client.query('SELECT count(*) FROM blob_file_versions')).result.rows).toEqual([[2n]])
    expect(await f.events()).toHaveLength(2)
    expect(await f.recipe.staged('file-stale')).toEqual(stale)
    expect(await f.readBytes(stale.sha256)).toEqual(bytes('stale edit'))
    const outcome = await f.native.client.operations.get('file-stale')
    expect(outcome).toMatchObject({ final: true, outcome: { outcome: 'rejected', rejectionCode: 'assert:file_revision_changed' } })
    f.native.assertHealthy()
  })

  it('keeps failed uploads out of history, retries one upload identity, validates receipts, and records expiry without claiming another copy', async () => {
    const f = await fixture()
    f.behavior.unavailable = true
    await expect(f.recipe.stage(bytes('recover upload'), input('recover-upload'), deadline())).rejects.toThrow('upload host unavailable')
    await expect(f.recipe.commit('recover-upload', deadline())).rejects.toThrow('BLOB_UPLOAD_NOT_STAGED')
    expect(await f.events()).toHaveLength(0)
    f.behavior.unavailable = false; f.behavior.loseUploadReply = true
    await expect(f.recipe.stage(bytes('recover upload'), input('recover-upload'), deadline())).rejects.toThrow('upload reply lost')
    const reopened = createBlobMetadataRecipe(f.options)
    const recovered = await reopened.stage(bytes('recover upload'), input('recover-upload'), deadline())
    expect(new Set(f.calls.map(call => call.cid)).size).toBe(1)
    expect(f.calls.every(call => bytesToHex(call.bytes) === bytesToHex(bytes('recover upload')))).toBe(true)
    await reopened.commit('recover-upload', deadline())
    expect(await f.events()).toHaveLength(1)
    f.behavior.incorrectDigest = true
    await expect(reopened.stage(bytes('bad digest'), { ...input('invalid-receipt'), path: 'documents/bad.txt' }, deadline())).rejects.toThrow('BLOB_UPLOAD_RECEIPT_MISMATCH')
    expect(await reopened.staged('invalid-receipt')).toBeNull()
    f.behavior.incorrectDigest = false; f.behavior.pinned = false
    await expect(reopened.stage(bytes('unpinned'), { ...input('unpinned'), path: 'documents/temporary.txt' }, deadline())).rejects.toThrow('BLOB_RETENTION_NOT_PINNED')
    expect(await reopened.staged('unpinned')).toBeNull()
    const expiring = createBlobMetadataRecipe({ ...f.options, retentionPolicy: 'accept-receipt-expiry' })
    const temporary = await expiring.stage(bytes('temporary'), { ...input('temporary'), path: 'documents/temporary.txt' }, deadline())
    await expiring.commit('temporary', deadline())
    expect(temporary.availability).toMatchObject({ additionalDurableCopies: 'unknown', receipt: { blob: { retention: { expires_at: 5000 } } } })
    const emitted = (await f.events()).map(event => event.payload as { reference: StagedFileReference } & Record<string, EventPayload>)
    expect(emitted.map(event => event.reference.sha256)).toEqual([recovered.sha256, temporary.sha256])
    expect((await f.native.client.query('SELECT count(*) FROM blob_file_versions')).result.rows).toEqual([[2n]])
    f.native.assertHealthy()
  })
})
