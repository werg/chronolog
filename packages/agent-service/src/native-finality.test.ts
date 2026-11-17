import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { spawnSync } from 'node:child_process'

import { signGenesis, type ClockPolicy } from '@chronolog/capabilities'
import { SignedInclusionFinalityProvider, MemoryOperationStore, createLedgerRecord, decodeLedgerRecord, decodeOrderingEvidence, membershipDescriptor,
  encodeOrderingEvidence, evaluateFinalitySnapshot, verifyPrefixCertificate } from '@chronolog/node-core'
import type { DurableOperationStore } from '@chronolog/node-core'
import { encodeCanonicalCbor, encodeEnvelope, generateEd25519KeyPair, utf8, type Ed25519KeyPair } from '@chronolog/protocol'
import { DurableFeedStore, PortableFeedTransport, feedIdFromPublicKey, webFeedCrypto, webFeedSigner } from '@chronolog/records'
import { afterEach, describe, expect, it } from 'vitest'

import { NativeFinalityService } from './finality-service.js'
import { NativeAgentStore } from './native-store.js'

const envelope = (text: string) => encodeEnvelope({ groupRoute: new Uint8Array(32).fill(1),
  messageType: 'candidate', encryptionEpoch: null, payload: utf8(text) })

const cleanup: Array<() => Promise<void> | void> = []
afterEach(async () => { for (const close of cleanup.splice(0).reverse()) await close() })

async function credentials(options: { readonly clockPolicy?: ClockPolicy; readonly identity?: Ed25519KeyPair;
  readonly executionManifestDigest?: Uint8Array } = {}) {
  const identity = options.identity ?? await generateEd25519KeyPair()
  const groupId = new Uint8Array(32).fill(1), schemaId = options.executionManifestDigest ?? new Uint8Array(32).fill(3)
  const genesis = await signGenesis({ groupId, schemaId, rootAdminPublicKey: identity.publicKeyBytes,
    schemaAdminPublicKey: identity.publicKeyBytes, capabilityLogFeed: utf8(feedIdFromPublicKey(identity.publicKeyBytes)),
    historyPolicy: { kind: 'coordinated', historyId: 'h_0123456789abcdef0123456789abcdef',
      authorityPublicKey: identity.publicKeyBytes, executionManifestDigest: schemaId },
    initialCapabilities: [], validationPolicies: [{ version: 1n, minimumValidators: 1n }],
    clockPolicy: options.clockPolicy ?? { cutoffLagMs: 0n, maxFutureSkewMs: 31_000n, heartbeatIntervalMs: 1_000n },
    resourcePolicy: { maxCandidateBytes: 1_000_000n, maxProgramNodes: 1_000n, maxPreconditions: 100n, maxMutations: 100n },
    encryptionSuite: 'HPKE-X25519-HKDF-SHA256-AES-256-GCM', createdAtMs: 1n,
  }, identity.privateKey)
  const descriptor = await membershipDescriptor(genesis, groupId)
  if (descriptor.history.kind !== 'coordinated') throw new Error('SIGNED_INCLUSION_REQUIRED')
  return { descriptor, configuration: descriptor.history, identity }
}

async function fixture(clockPolicy?: ClockPolicy) {
  const credentialsValue = await credentials(clockPolicy === undefined ? {} : { clockPolicy })
  const directory = await mkdtemp(join(tmpdir(), 'chronolog-agent-authority-'))
  cleanup.push(() => rm(directory, { recursive: true, force: true }))
  const path = join(directory, 'agent.sqlite')
  const store = new NativeAgentStore(path)
  cleanup.push(() => store.close())
  const clock = { now: 1_000 }
  return { ...credentialsValue, store, path, clock, now: () => clock.now }
}

async function metadataFixture() {
  const { descriptor, configuration, identity } = await credentials()
  const values = new Map<string, Uint8Array>()
  const store: DurableOperationStore = {
    get: async (key) => values.get(key)?.slice() ?? null,
    put: async (key, bytes) => { values.set(key, bytes.slice()) },
  }
  const prefix = `agent/authority/${configuration.historyId}/`
  const clock = { now: 1_000 }
  return { descriptor, configuration, identity, store, values, logKey: `record-log/${configuration.historyId}`,
    configurationKey: `${prefix}configuration`, certificateKey: `${prefix}certificate`,
    payloadIndexKey: `${prefix}payload-reservations`,
    clock, now: () => clock.now }
}

describe('native signed-inclusion finality service', () => {
  it('authenticates timing and history before touching storage', async () => {
    const f = await metadataFixture()
    const tampered = structuredClone(f.descriptor)
    const changed = { ...tampered, genesis: { ...tampered.genesis,
      manifest: { ...tampered.genesis.manifest, clockPolicy: { ...tampered.genesis.manifest.clockPolicy, cutoffLagMs: 500n } } } }
    await expect(NativeFinalityService.open({ ...f, descriptor: changed })).rejects.toThrow('ENROLLMENT_DESCRIPTOR_INVALID')
    expect(f.values.size).toBe(0)
    const invalid = await credentials({ identity: f.identity,
      clockPolicy: { cutoffLagMs: 0n, maxFutureSkewMs: 10n, heartbeatIntervalMs: 0n } })
    await expect(NativeFinalityService.open({ ...f, descriptor: invalid.descriptor })).rejects.toThrow('FINALITY_CLOCK_POLICY_INVALID')
    expect(f.values.size).toBe(0)
  })

  it('does not sign for a different provider selected by genesis', async () => {
    const f = await metadataFixture()
    const genesis = await signGenesis({ ...f.descriptor.genesis.manifest,
      historyPolicy: { ...f.descriptor.genesis.manifest.historyPolicy!, providerId: 'different-provider-v1' },
    }, f.identity.privateKey)
    const descriptor = await membershipDescriptor(genesis, f.descriptor.groupRoute)
    await expect(NativeFinalityService.open({ ...f, descriptor })).rejects.toThrow('FINALITY_SERVICE_PROVIDER_MISMATCH')
    expect(f.values.size).toBe(0)
  })

  it.each([
    { cutoffLagMs: 0n, maxFutureSkewMs: 0n, heartbeatIntervalMs: 60_001n },
    { cutoffLagMs: BigInt(Number.MAX_SAFE_INTEGER), maxFutureSkewMs: 1n, heartbeatIntervalMs: 1_000n },
  ])('refuses an unsupported signed clock without initializing storage, case %#', async (clockPolicy) => {
    const f = await metadataFixture(), descriptor = (await credentials({ clockPolicy, identity: f.identity })).descriptor
    await expect(NativeFinalityService.open({ ...f, descriptor })).rejects.toThrow('FINALITY_CLOCK_POLICY_INVALID')
    expect(f.values.size).toBe(0)
  })

  it('owns the verified descriptor snapshot and refuses later clock changes on the same lineage', async () => {
    const f = await metadataFixture()
    const input = structuredClone(f.descriptor)
    const opening = NativeFinalityService.open({ ...f, descriptor: input })
    input.history.genesisDigest.fill(9)
    Object.assign(input.genesis.manifest.clockPolicy, { cutoffLagMs: 9_000n })
    const finality = await opening
    await finality.append(envelope('immutable signed timing'))
    await finality.certify()
    expect((await evaluateFinalitySnapshot(f.configuration, (await finality.read()).entries)).closedThroughMs).toBe(1_000n)
    const changed = await credentials({ clockPolicy: { cutoffLagMs: 250n, maxFutureSkewMs: 31_000n, heartbeatIntervalMs: 1_000n }, identity: f.identity })
    const before = structuredClone(f.values)
    await expect(NativeFinalityService.open({ ...f, descriptor: changed.descriptor })).rejects.toThrow('AUTHORITY_CONFIGURATION_MISMATCH')
    expect(f.values).toEqual(before)
  })

  it('certifies only small descriptors while retaining exact detached payloads before commitment', async () => {
    const f = await fixture(), authority = await NativeFinalityService.open(f)
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
    const reopened = await NativeFinalityService.open(f)
    expect(await reopened.getPayload(descriptor.payloadHash)).toEqual(payload)
  })

  it('fences another process and durably reopens exact retry identities, closures and receipt head', async () => {
    const f = await fixture()
    const authority = await NativeFinalityService.open(f)
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
    const reopened = await NativeFinalityService.open({ ...f, store: reopenedStore, continuity: certificate })
    expect(await reopened.append(envelope('one'))).toEqual(entry)
    expect(await reopened.head()).toEqual({ historyId: certificate.historyId, position: 2, root: certificate.root })
    await verifyPrefixCertificate(await reopened.certify(), f.configuration)
    expect((await reopened.append(envelope('two'))).position).toBe(3)
  })

  it('atomically refuses exhausted quotas without consuming a position', async () => {
    const f = await fixture()
    const quotaBytes = (await createLedgerRecord(envelope('one'))).recordBytes.length
    const authority = await NativeFinalityService.open({ ...f, recordQuotaBytes: quotaBytes })
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

  it('bounds detached bodies separately, including across exact retries and reopen', async () => {
    const f = await metadataFixture(), body = envelope('one')
    const authority = await NativeFinalityService.open({ ...f, payloadQuotaBytes: body.length })
    const entry = await authority.append(body)
    await expect(authority.append(envelope('two'))).rejects.toThrow('FINALITY_PAYLOAD_QUOTA_EXCEEDED')
    expect((await authority.head()).position).toBe(1)
    expect(await authority.storageUsage()).toMatchObject({ reservedPayloadBytes: body.length, payloadQuotaBytes: body.length })
    const reopened = await NativeFinalityService.open({ ...f, payloadQuotaBytes: body.length })
    expect(await reopened.append(body)).toEqual(entry)
    expect(await reopened.storageUsage()).toEqual(await authority.storageUsage())
    const before = structuredClone(f.values)
    await expect(NativeFinalityService.open({ ...f, payloadQuotaBytes: body.length - 1 })).rejects.toThrow('FINALITY_PAYLOAD_QUOTA_EXCEEDED')
    expect(f.values).toEqual(before)
  })

  it('retains a bounded reservation after a lost body reply and reuses it on retry', async () => {
    const f = await metadataFixture(), body = envelope('reserved')
    let fail = true
    const store: DurableOperationStore = { get: key => f.store.get(key), async put(key, bytes) {
      await f.store.put(key, bytes)
      if (key.includes('/payload/') && fail) { fail = false; throw new Error('lost body acknowledgment') }
    } }
    const authority = await NativeFinalityService.open({ ...f, store, payloadQuotaBytes: body.length })
    await expect(authority.append(body)).rejects.toThrow('lost body acknowledgment')
    expect((await authority.head()).position).toBe(0)
    const reopened = await NativeFinalityService.open({ ...f, payloadQuotaBytes: body.length })
    await expect(reopened.append(envelope('another-body'))).rejects.toThrow('FINALITY_PAYLOAD_QUOTA_EXCEEDED')
    expect((await reopened.append(body)).position).toBe(1)
    expect((await reopened.storageUsage()).reservedPayloadBytes).toBe(body.length)
  })

  it('does not store a new body when the retained record quota is already full', async () => {
    const f = await metadataFixture(), one = envelope('one'), two = envelope('two')
    const descriptor = await createLedgerRecord(one)
    const authority = await NativeFinalityService.open({ ...f, recordQuotaBytes: descriptor.recordBytes.length })
    await authority.append(one)
    const before = structuredClone(f.values)
    await expect(authority.append(two)).rejects.toThrow('RECORD_LOG_QUOTA_EXCEEDED')
    expect(f.values).toEqual(before)
  })

  it('refuses missing body accounting instead of silently resetting its budget', async () => {
    const f = await metadataFixture(), authority = await NativeFinalityService.open(f)
    await authority.append(envelope('one'))
    f.values.delete(f.payloadIndexKey)
    const before = structuredClone(f.values)
    await expect(NativeFinalityService.open(f)).rejects.toThrow('FINALITY_PAYLOAD_STATE_MISSING')
    expect(f.values).toEqual(before)
  })

  it('recovers a commit whose acknowledgment was lost and leaves failed writes unapplied', async () => {
    const f = await fixture()
    let loseResponse = false, failBeforeWrite = false
    const store: DurableOperationStore = {
      get: (key) => f.store.get(key),
      put: async (key, bytes) => {
        if (key.startsWith('record-log/') && failBeforeWrite) throw new Error('disk unavailable')
        await f.store.put(key, bytes)
        if (key.startsWith('record-log/') && loseResponse) { loseResponse = false; throw new Error('lost acknowledgment') }
      },
    }
    const authority = await NativeFinalityService.open({ ...f, store })
    loseResponse = true
    await expect(authority.append(envelope('one'))).rejects.toThrow('lost acknowledgment')
    const reopened = await NativeFinalityService.open({ ...f, store })
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
    const authority = await NativeFinalityService.open(f)
    await authority.append(envelope('one'))
    const checkpoint = await authority.certify()
    const different = await credentials({ identity: f.identity, executionManifestDigest: new Uint8Array(32).fill(9) })
    await expect(NativeFinalityService.open({ ...f, descriptor: different.descriptor }))
      .rejects.toThrow('AUTHORITY_CONFIGURATION_MISMATCH')
    await expect(NativeFinalityService.open({ ...f, store: new MemoryOperationStore(), continuity: checkpoint }))
      .rejects.toThrow('AUTHORITY_CONTINUITY_NOT_ESTABLISHED')
    await expect(NativeFinalityService.open({ ...f, continuity: { ...checkpoint, root: '0'.repeat(64) } }))
      .rejects.toThrow('AUTHORITY_CONTINUITY_NOT_ESTABLISHED')
  })

  it.each(['before-log', 'after-log', 'before-payload-index', 'after-payload-index', 'before-configuration', 'after-configuration'] as const)(
    'initializes the empty log and payload index before configuration and recovers interruption %s', async (boundary) => {
      const f = await metadataFixture(), writes: string[] = []
      const store: DurableOperationStore = {
        get: (key) => f.store.get(key),
        put: async (key, bytes) => {
          writes.push(key)
          const target = boundary.endsWith('log') ? f.logKey : boundary.endsWith('payload-index') ? f.payloadIndexKey : f.configurationKey
          if (key === target && boundary.startsWith('before-')) throw new Error('setup interrupted')
          await f.store.put(key, bytes)
          if (key === target && boundary.startsWith('after-')) throw new Error('setup interrupted')
        },
      }
      await expect(NativeFinalityService.open({ ...f, store })).rejects.toThrow('setup interrupted')
      expect(writes).toEqual(boundary.endsWith('log') ? [f.logKey] : boundary.endsWith('payload-index')
        ? [f.logKey, f.payloadIndexKey] : [f.logKey, f.payloadIndexKey, f.configurationKey])
      expect(f.values.has(f.configurationKey)).toBe(boundary === 'after-configuration')
      expect(f.values.has(f.logKey)).toBe(boundary !== 'before-log')
      expect(f.values.has(f.payloadIndexKey)).toBe(['after-payload-index', 'before-configuration', 'after-configuration'].includes(boundary))
      const recovered = await NativeFinalityService.open(f)
      expect((await recovered.head()).position).toBe(0)
      expect((await recovered.append(envelope('one'))).position).toBe(1)
    },
  )

  it.each([false, true])('refuses a missing established log without modifying surviving metadata (certified: %s)', async (certified) => {
    const f = await metadataFixture(), authority = await NativeFinalityService.open(f)
    if (certified) { await authority.append(envelope('one')); await authority.certify() }
    f.values.delete(f.logKey)
    const before = structuredClone(f.values)
    await expect(NativeFinalityService.open(f)).rejects.toThrow('AUTHORITY_CONTINUITY_NOT_ESTABLISHED')
    expect(f.values).toEqual(before)
    // A still-live owner cannot recreate the missing prefix either.
    await expect(authority.certify()).rejects.toThrow('RECORD_LOG_MISSING')
    expect(f.values).toEqual(before)
  })

  it.each(['empty', 'conflicting'] as const)('enforces a surviving certificate against a %s replacement log', async (damage) => {
    const f = await metadataFixture(), authority = await NativeFinalityService.open(f)
    await authority.append(envelope('one'))
    await authority.certify()
    const replacement = new MemoryOperationStore()
    const other = await NativeFinalityService.open({ ...f, store: replacement })
    if (damage === 'conflicting') {
      await other.append(envelope('replacement'))
      await other.certify()
      expect((await other.head()).position).toBe((await authority.head()).position)
    }
    f.values.set(f.logKey, (await replacement.get(f.logKey))!)
    const before = structuredClone(f.values)
    await expect(NativeFinalityService.open(f)).rejects.toThrow('AUTHORITY_CONTINUITY_NOT_ESTABLISHED')
    expect(f.values).toEqual(before)
  })

  it.each(['encoding', 'kind', 'signature', 'configuration'] as const)('refuses a retained certificate with invalid %s before changing storage', async (damage) => {
    const f = await metadataFixture(), authority = await NativeFinalityService.open(f)
    const entry = await authority.append(envelope('one'))
    const certificate = await authority.certify()
    let bytes: Uint8Array
    if (damage === 'encoding') bytes = encodeCanonicalCbor([])
    else if (damage === 'kind') bytes = encodeOrderingEvidence({ kind: 'ordered-entry', entry })
    else if (damage === 'signature') {
      certificate.signature[0]! ^= 1
      bytes = encodeOrderingEvidence({ kind: 'prefix-certificate', certificate })
    } else {
      const different = await credentials({ identity: f.identity, executionManifestDigest: new Uint8Array(32).fill(9) })
      const other = await NativeFinalityService.open({ ...f, store: new MemoryOperationStore(), descriptor: different.descriptor })
      await other.append(envelope('one'))
      bytes = encodeOrderingEvidence({ kind: 'prefix-certificate', certificate: await other.certify() })
    }
    f.values.set(f.certificateKey, bytes)
    // Even without configuration/log, invalid retained evidence is never treated as
    // permission to initialize or overwrite this authority's state.
    f.values.delete(f.configurationKey)
    f.values.delete(f.logKey)
    const before = structuredClone(f.values)
    await expect(NativeFinalityService.open(f)).rejects.toThrow('AUTHORITY_RETAINED_CERTIFICATE_INVALID')
    expect(f.values).toEqual(before)
  })

  it('reopens committed appends ahead of the retained certificate and preserves their retry positions', async () => {
    const f = await metadataFixture(), authority = await NativeFinalityService.open(f)
    const first = await authority.append(envelope('one'))
    await authority.certify()
    const second = await authority.append(envelope('two'))
    const reopened = await NativeFinalityService.open(f)
    expect(await reopened.append(envelope('one'))).toEqual(first)
    expect(await reopened.append(envelope('two'))).toEqual(second)
    const certificate = await reopened.certify()
    expect(certificate.position).toBe(second.position + 1)
    const proof = await evaluateFinalitySnapshot(f.configuration, (await reopened.read()).entries)
    expect(proof.records.map(record => record.entry)).toEqual([first, second])
    expect(proof.closures).toHaveLength(2)
  })

  it('requires an independent continuity floor to detect a self-consistent whole-volume rollback', async () => {
    const f = await metadataFixture(), authority = await NativeFinalityService.open(f)
    await authority.append(envelope('one'))
    await authority.certify()
    const backup = structuredClone(f.values)
    await authority.append(envelope('two'))
    const latest = await authority.certify()
    f.values.clear()
    for (const [key, bytes] of backup) f.values.set(key, bytes)
    await expect(NativeFinalityService.open({ ...f, continuity: latest })).rejects.toThrow('AUTHORITY_CONTINUITY_NOT_ESTABLISHED')
    expect(f.values).toEqual(backup)
  })

  it('supplies portable range evidence that peers can relay without the authority', async () => {
    const f = await fixture()
    const authority = await NativeFinalityService.open(f)
    await Promise.all(['one', 'two', 'three'].map((text) => authority.append(envelope(text))))
    const captured: Uint8Array[] = []
    const sink = { putEvidence: async (bytes: Uint8Array) => { captured.push(bytes) } }
    const first = await authority.certifiedRead({ limit: 1 })
    for (const entry of first.entries) await sink.putEvidence(encodeOrderingEvidence({ kind: 'ordered-entry', entry }))
    await sink.putEvidence(encodeOrderingEvidence({ kind: 'prefix-certificate', certificate: first.certificate }))
    const peer = await SignedInclusionFinalityProvider.open(f.configuration, new MemoryOperationStore())
    for (const bytes of captured.splice(0)) await peer.ingest(decodeOrderingEvidence(bytes))
    expect(peer.progress.finalThrough).toBe(0)
    await authority.share(sink, { after: first.entries.at(-1)!.position })
    for (const bytes of captured.reverse()) await peer.ingest(decodeOrderingEvidence(bytes))
    expect(peer.progress.finalThrough).toBe(4)
    expect(peer.snapshot().closedThroughMs).toBe(1_000n)
    const third = await SignedInclusionFinalityProvider.open(f.configuration, new MemoryOperationStore())
    for (const evidence of [...peer.evidence()].reverse()) await third.ingest(evidence)
    expect(third.progress).toEqual(peer.progress)
  })

  it('shares every page of a captured prefix and leaves concurrent appends for the next call', async () => {
    const f = await metadataFixture(), authority = await NativeFinalityService.open(f)
    await Promise.all(Array.from({ length: 65 }, (_, index) => authority.append(envelope(`proposal-${index}`))))
    const captured: Uint8Array[] = []
    let added = false, laterPosition = 0
    const shared = await authority.share({ putEvidence: async bytes => {
      captured.push(bytes.slice())
      const evidence = decodeOrderingEvidence(bytes)
      if (!added && evidence.kind === 'ordered-entry' && evidence.entry.position === 64) {
        added = true
        laterPosition = (await authority.append(envelope('after-captured-prefix'))).position
      }
    } })
    expect(laterPosition).toBe(67)
    expect(shared.position).toBe(66)
    const evidence = captured.map(decodeOrderingEvidence)
    expect(evidence.flatMap(item => item.kind === 'ordered-entry' ? [item.entry.position] : []))
      .toEqual(Array.from({ length: 66 }, (_, index) => index + 1))
    expect(evidence.at(-1)).toMatchObject({ kind: 'prefix-certificate', certificate: shared })
    expect((await authority.head()).position).toBe(67)
    const peer = await SignedInclusionFinalityProvider.open(f.configuration, new MemoryOperationStore())
    await peer.ingestBatch(evidence)
    expect(peer.progress.finalThrough).toBe(66)

    const resumed: Uint8Array[] = []
    const next = await authority.share({ putEvidence: async bytes => { resumed.push(bytes.slice()) } }, { after: shared.position })
    expect(next.position).toBe(68)
    expect(resumed.map(decodeOrderingEvidence).flatMap(item => item.kind === 'ordered-entry' ? [item.entry.position] : []))
      .toEqual([67, 68])
    await peer.ingestBatch(resumed.map(decodeOrderingEvidence))
    expect(peer.progress.finalThrough).toBe(68)
  })

  it.each(['entry', 'certificate'] as const)('propagates a lost %s sink acknowledgment and retries exact evidence', async (boundary) => {
    const f = await metadataFixture(), authority = await NativeFinalityService.open(f)
    await Promise.all(['one', 'two', 'three'].map(text => authority.append(envelope(text))))
    const peer = await SignedInclusionFinalityProvider.open(f.configuration, new MemoryOperationStore())
    const captured: Uint8Array[] = [], lost = new Error('sink acknowledgment lost')
    let fail = true
    const sink = { putEvidence: async (bytes: Uint8Array) => {
      captured.push(bytes.slice())
      const evidence = decodeOrderingEvidence(bytes)
      await peer.ingest(evidence)
      if (fail && (boundary === 'entry' ? evidence.kind === 'ordered-entry' && evidence.entry.position === 2
        : evidence.kind === 'prefix-certificate')) {
        fail = false
        throw lost
      }
    } }
    await expect(authority.share(sink)).rejects.toBe(lost)
    const firstAttempt = captured.splice(0), beforeRetry = await authority.head()
    expect(await authority.share(sink)).toEqual(beforeRetry)
    expect(captured.slice(0, firstAttempt.length)).toEqual(firstAttempt)
    expect(peer.progress.finalThrough).toBe(4)
    expect((await authority.head()).position).toBe(4)
  })

  it('validates a share cursor before closing time and accepts an already shared head', async () => {
    const f = await metadataFixture(), authority = await NativeFinalityService.open(f)
    await authority.append(envelope('one'))
    const before = structuredClone(f.values), captured: Uint8Array[] = []
    const sink = { putEvidence: async (bytes: Uint8Array) => { captured.push(bytes.slice()) } }
    for (const after of [-1, 1.5, NaN, Infinity, Number.MAX_SAFE_INTEGER + 1]) {
      await expect(authority.share(sink, { after })).rejects.toThrow('AUTHORITY_RANGE_INVALID')
    }
    await expect(authority.share(sink, { after: 2 })).rejects.toThrow('AUTHORITY_RANGE_AHEAD')
    expect(f.values).toEqual(before)
    expect(captured).toHaveLength(0)
    const shared = await authority.share(sink)
    captured.length = 0
    expect(await authority.share(sink, { after: shared.position })).toEqual(shared)
    expect(captured.map(decodeOrderingEvidence)).toEqual([
      expect.objectContaining({ kind: 'prefix-certificate', certificate: expect.objectContaining(shared) }),
    ])
  })

  it('cancels sharing between acknowledged writes without publishing a partial certificate', async () => {
    const f = await metadataFixture(), authority = await NativeFinalityService.open(f)
    await authority.append(envelope('one'))
    const stopped = new AbortController(), reason = new Error('sharing stopped'), captured: Uint8Array[] = []
    const before = structuredClone(f.values)
    stopped.abort(reason)
    await expect(authority.share({ putEvidence: async bytes => { captured.push(bytes.slice()) } }, { signal: stopped.signal }))
      .rejects.toBe(reason)
    expect(f.values).toEqual(before)
    expect(captured).toHaveLength(0)
    const during = new AbortController()
    await expect(authority.share({ putEvidence: async bytes => {
      captured.push(bytes.slice())
      during.abort(reason)
    } }, { signal: during.signal })).rejects.toBe(reason)
    expect(captured.map(decodeOrderingEvidence)).toEqual([
      expect.objectContaining({ kind: 'ordered-entry', entry: expect.objectContaining({ position: 1 }) }),
    ])
    const retried: Uint8Array[] = []
    expect((await authority.share({ putEvidence: async bytes => { retried.push(bytes.slice()) } })).position).toBe(2)
    expect(retried[0]).toEqual(captured[0])
    expect(decodeOrderingEvidence(retried.at(-1)!)).toMatchObject({ kind: 'prefix-certificate', certificate: { position: 2 } })
  })

  it('recovers a durable closure after certificate publication fails and the provider clock moves backward', async () => {
    const f = await fixture()
    let failCertificate = true
    const store: DurableOperationStore = {
      get: (key) => f.store.get(key),
      put: async (key, bytes) => {
        if (key.endsWith('/certificate') && failCertificate) throw new Error('certificate response lost')
        await f.store.put(key, bytes)
      },
    }
    const authority = await NativeFinalityService.open({ ...f, store })
    const original = await authority.append(envelope('one'))
    await expect(authority.certify()).rejects.toThrow('certificate response lost')
    expect((await authority.head()).position).toBe(2)
    failCertificate = false
    f.clock.now = 500
    const reopened = await NativeFinalityService.open({ ...f, store })
    expect(await reopened.append(envelope('one'))).toEqual(original)
    const proof = await reopened.certifiedRead()
    expect(proof.certificate.position).toBe(2)
    expect(proof.hasMore).toBe(false)
    expect((await evaluateFinalitySnapshot(f.configuration, proof.entries)).closedThroughMs).toBe(1_000n)
  })

  it('publishes complete closure evidence while the application receipt head is idle', async () => {
    const f = await fixture({ cutoffLagMs: 100n, maxFutureSkewMs: 100n, heartbeatIntervalMs: 5n })
    const authority = await NativeFinalityService.open(f)
    await authority.certify()
    expect((await authority.head()).position).toBe(0)
    const transport = new PortableFeedTransport({ store: await DurableFeedStore.open(new MemoryOperationStore(), webFeedCrypto),
      signer: webFeedSigner(feedIdFromPublicKey(f.identity.publicKeyBytes), f.identity.privateKey), crypto: webFeedCrypto })
    cleanup.push(() => transport.close())
    await transport.publish(envelope('queued-before-service'))
    const stopped = new AbortController(), running = authority.serve(transport, stopped.signal)
    const policy = await SignedInclusionFinalityProvider.open(f.configuration, new MemoryOperationStore())
    const frontier = async () => {
      for (const item of await transport.evidenceHistory()) await policy.ingest(decodeOrderingEvidence(item.bytes))
      return policy.snapshot().closedThroughMs
    }
    try {
      await expect.poll(frontier).toBe(900n)
      expect(policy.snapshot().records).toHaveLength(1)
      f.clock.now = 1_200
      await expect.poll(frontier).toBe(1_100n)
      expect(policy.snapshot().records).toHaveLength(1)
      const closedHead = await authority.head()
      f.clock.now = 10_000
      for (let idle = 0; idle < 20; idle += 1) {
        f.clock.now += 1_000
        expect(await authority.certify()).toMatchObject(closedHead)
      }
      const reopened = await NativeFinalityService.open(f)
      expect(await reopened.certify()).toMatchObject(closedHead)
      expect((await evaluateFinalitySnapshot(f.configuration, (await reopened.read()).entries)).closedThroughMs).toBe(1_100n)
    } finally { stopped.abort(); await running }
  })

  it.each(['certify', 'certifiedRead'] as const)('does not advance the %s clock while asynchronous reads block queued appenders', async (method) => {
    const f = await metadataFixture()
    let advanceDuringRead = false
    const store: DurableOperationStore = {
      get: async key => {
        if (advanceDuringRead && key === f.logKey) { advanceDuringRead = false; f.clock.now = 5_000 }
        return f.store.get(key)
      },
      put: (key, bytes) => f.store.put(key, bytes),
    }
    const authority = await NativeFinalityService.open({ ...f, store })
    await authority.append(envelope('previously-included'))
    advanceDuringRead = true
    const closing = authority[method]()
    const pending = authority.append(envelope('published-while-closure-was-verifying'))
    await closing
    const entry = await pending
    const proof = await evaluateFinalitySnapshot(f.configuration, (await authority.read()).entries)
    expect(proof.closedThroughMs).toBe(1_000n)
    expect(proof.records.find(record => record.entry.position === entry.position)!.admissionFloorMs).toBe(1_000n)
    // A later closure can use the newer clock, after that queued receipt exists.
    await authority.certify()
    expect((await evaluateFinalitySnapshot(f.configuration, (await authority.read()).entries)).closedThroughMs).toBe(5_000n)
  })

  it('does not close additional author time merely to replay exact retained submissions', async () => {
    const f = await fixture({ cutoffLagMs: 0n, maxFutureSkewMs: 31_000n, heartbeatIntervalMs: 60_000n })
    const authority = await NativeFinalityService.open({ ...f, now: () => f.clock.now++ })
    const transport = new PortableFeedTransport({ store: await DurableFeedStore.open(new MemoryOperationStore(), webFeedCrypto),
      signer: webFeedSigner(feedIdFromPublicKey(f.identity.publicKeyBytes), f.identity.privateKey), crypto: webFeedCrypto })
    cleanup.push(() => transport.close())
    const payload = envelope('same-retained-submission')
    await transport.publish(payload)
    await transport.publish(payload)
    // End this replaying subscription after its retained history, before the
    // independent closure timer. Duplicate feed records have one receipt.
    transport.subscribe = async function* () { yield* await transport.history() }
    await authority.serve(transport)
    const proof = await evaluateFinalitySnapshot(f.configuration, (await authority.read()).entries)
    expect(proof.records).toHaveLength(1)
    expect(proof.closures).toHaveLength(1)
    expect(proof.closedThroughMs).toBe(1_000n)
  })
})
