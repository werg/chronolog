import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { spawnSync } from 'node:child_process'

import { CoordinatedHistoryPolicy, MemoryOperationStore, createLedgerRecord, decodeLedgerRecord, decodeOrderingEvidence, verifyPrefixCertificate } from '@chronolog/node-core'
import type { CoordinatedHistoryConfiguration, DurableOperationStore } from '@chronolog/node-core'
import { encodeEnvelope, generateEd25519KeyPair, utf8 } from '@chronolog/protocol'
import { afterEach, describe, expect, it } from 'vitest'

import { NativeAuthority } from './authority.js'
import { NativeAgentStore } from './native-store.js'

const envelope = (text: string) => encodeEnvelope({ groupRoute: new Uint8Array(32).fill(1),
  messageType: 'candidate', encryptionEpoch: null, payload: utf8(text) })

const cleanup: Array<() => Promise<void> | void> = []
afterEach(async () => { for (const close of cleanup.splice(0).reverse()) await close() })

async function fixture() {
  const identity = await generateEd25519KeyPair()
  const configuration: CoordinatedHistoryConfiguration = {
    kind: 'coordinated', historyId: 'h_0123456789abcdef0123456789abcdef', authorityPublicKey: identity.publicKeyBytes,
    groupId: new Uint8Array(32).fill(1), genesisDigest: new Uint8Array(32).fill(2), executionManifestDigest: new Uint8Array(32).fill(3),
  }
  const directory = await mkdtemp(join(tmpdir(), 'chronolog-agent-authority-'))
  cleanup.push(() => rm(directory, { recursive: true, force: true }))
  const path = join(directory, 'agent.sqlite')
  const store = new NativeAgentStore(path)
  cleanup.push(() => store.close())
  return { configuration, identity, store, path }
}

describe('native fixed authority', () => {
  it('certifies only small descriptors while retaining exact detached payloads before commitment', async () => {
    const f = await fixture(), authority = await NativeAuthority.open(f)
    const payload = envelope('large-content'.repeat(40_000)), entry = await authority.append(payload)
    const descriptor = decodeLedgerRecord(entry.bytes)
    expect(entry.bytes.length).toBeLessThan(256)
    expect(descriptor.kind).toBe('candidate')
    expect(descriptor.inlinePayload).toBeNull()
    expect(await authority.getPayload(descriptor.payloadHash)).toEqual(payload)
    expect(await authority.appendLedgerRecord(entry.bytes)).toEqual(entry)
    const missing = await createLedgerRecord(envelope('unavailable'))
    await expect(authority.appendLedgerRecord(missing.recordBytes)).rejects.toThrow('LEDGER_PAYLOAD_UNAVAILABLE')
    expect((await authority.head()).position).toBe(1)
    const reopened = await NativeAuthority.open(f)
    expect(await reopened.getPayload(descriptor.payloadHash)).toEqual(payload)
  })

  it('fences another process and durably reopens exact retry identities, order and head', async () => {
    const f = await fixture()
    const authority = await NativeAuthority.open(f)
    const entry = await authority.append(envelope('one'))
    const certificate = await authority.certify()
    expect(() => new NativeAgentStore(f.path)).toThrow('AGENT_STORE_IN_USE')
    const second = spawnSync(process.execPath, ['--input-type=module', '-e', `
      import { DatabaseSync } from 'node:sqlite';
      const db = new DatabaseSync(process.argv[1]);
      db.exec('PRAGMA busy_timeout = 0');
      db.exec('BEGIN IMMEDIATE');
    `, f.path], { encoding: 'utf8' })
    expect(second.status).not.toBe(0)
    expect(second.stderr).toMatch(/locked|busy/u)
    f.store.close()
    const reopenedStore = new NativeAgentStore(f.path)
    cleanup.push(() => reopenedStore.close())
    const reopened = await NativeAuthority.open({ ...f, store: reopenedStore, continuity: certificate })
    expect(await reopened.append(envelope('one'))).toEqual(entry)
    expect(await reopened.head()).toEqual({ historyId: entry.historyId, position: 1, root: entry.root })
    await verifyPrefixCertificate(await reopened.certify(), f.configuration)
    expect((await reopened.append(envelope('two'))).position).toBe(2)
  })

  it('atomically refuses exhausted quotas without consuming a position', async () => {
    const f = await fixture()
    const quotaBytes = (await createLedgerRecord(envelope('one'))).recordBytes.length
    const authority = await NativeAuthority.open({ ...f, quotaBytes })
    const original = await authority.append(envelope('one'))
    await expect(authority.append(envelope('two'))).rejects.toThrow('RECORD_LOG_QUOTA_EXCEEDED')
    expect((await authority.head()).position).toBe(1)
    expect(await authority.append(envelope('one'))).toEqual(original)
    const isolated = new NativeAgentStore(':memory:', { quotaBytes: 3, maxValueBytes: 4 })
    cleanup.push(() => isolated.close())
    await isolated.put('state', utf8('one'))
    await expect(isolated.put('state', utf8('four'))).rejects.toThrow('AGENT_STORE_QUOTA_EXCEEDED')
    expect(await isolated.get('state')).toEqual(utf8('one'))
    await isolated.put('state', utf8('ok'))
    expect(isolated.usageBytes()).toBe(2)
  })

  it('recovers a commit whose acknowledgment was lost and leaves failed writes unapplied', async () => {
    const f = await fixture()
    let loseResponse = true, failBeforeWrite = false
    const store: DurableOperationStore = {
      get: (key) => f.store.get(key),
      put: async (key, bytes) => {
        if (key.startsWith('record-log/') && failBeforeWrite) throw new Error('disk unavailable')
        await f.store.put(key, bytes)
        if (key.startsWith('record-log/') && loseResponse) { loseResponse = false; throw new Error('lost acknowledgment') }
      },
    }
    const authority = await NativeAuthority.open({ ...f, store })
    await expect(authority.append(envelope('one'))).rejects.toThrow('lost acknowledgment')
    const reopened = await NativeAuthority.open({ ...f, store })
    const recovered = await reopened.append(envelope('one'))
    expect(recovered.position).toBe(1)
    failBeforeWrite = true
    await expect(reopened.append(envelope('two'))).rejects.toThrow('disk unavailable')
    expect((await reopened.head()).position).toBe(1)
    failBeforeWrite = false
    expect((await reopened.append(envelope('two'))).position).toBe(2)
  })

  it('pins configuration and refuses a recovery checkpoint newer than the retained volume', async () => {
    const f = await fixture()
    const authority = await NativeAuthority.open(f)
    await authority.append(envelope('one'))
    const checkpoint = await authority.certify()
    await expect(NativeAuthority.open({ ...f, configuration: { ...f.configuration, executionManifestDigest: new Uint8Array(32).fill(9) } }))
      .rejects.toThrow('AUTHORITY_CONFIGURATION_MISMATCH')
    await expect(NativeAuthority.open({ ...f, store: new MemoryOperationStore(), continuity: checkpoint }))
      .rejects.toThrow('AUTHORITY_CONTINUITY_NOT_ESTABLISHED')
    await expect(NativeAuthority.open({ ...f, continuity: { ...checkpoint, root: '0'.repeat(64) } }))
      .rejects.toThrow('AUTHORITY_CONTINUITY_NOT_ESTABLISHED')
  })

  it('supplies portable range evidence that peers can relay without the authority', async () => {
    const f = await fixture()
    const authority = await NativeAuthority.open(f)
    await Promise.all(['one', 'two', 'three'].map((text) => authority.append(envelope(text))))
    const captured: Uint8Array[] = []
    const sink = { putEvidence: async (bytes: Uint8Array) => { captured.push(bytes) } }
    const first = await authority.share(sink, { limit: 1 })
    const peer = await CoordinatedHistoryPolicy.open(f.configuration, new MemoryOperationStore())
    for (const bytes of captured.splice(0)) await peer.ingest(decodeOrderingEvidence(bytes))
    expect(peer.progress.finalThrough).toBe(0)
    await authority.share(sink, { after: first.position, limit: 2 })
    for (const bytes of captured.reverse()) await peer.ingest(decodeOrderingEvidence(bytes))
    expect(peer.progress.finalThrough).toBe(3)
    const third = await CoordinatedHistoryPolicy.open(f.configuration, new MemoryOperationStore())
    for (const evidence of [...peer.evidence()].reverse()) await third.ingest(evidence)
    expect(third.progress).toEqual(peer.progress)
  })
})
