import { bytesToHex, sha256 } from '@chronolog/canonical'
import { assertCanonicalCbor, encodeCanonicalCbor, encodeEnvelope, generateEd25519KeyPair, type CborValue } from '@chronolog/protocol'
import { describe, expect, it, vi } from 'vitest'

import { SignedInclusionFinalityProvider, ReferenceRecordLog, createPrefixAuthority } from './history-policy.js'
import {
  MAX_LEDGER_INLINE_PAYLOAD_BYTES, MAX_LEDGER_PAYLOAD_BYTES, MAX_LEDGER_RECORD_BYTES,
  createLedgerRecord, decodeLedgerRecord, resolveLedgerPayload, verifyLedgerPayload,
  type LedgerRecord,
} from './ledger-record.js'
import { MemoryOperationStore } from './operations.js'

const route = new Uint8Array(32).fill(7)
const epoch = encodeCanonicalCbor(42n)
const candidate = (size = 128) => encodeEnvelope({ groupRoute: route, messageType: 'candidate', encryptionEpoch: epoch,
  payload: new Uint8Array(size).fill(19) })
const control = (kind: 'capability' | 'epoch-manifest', size = 32) => encodeEnvelope({
  groupRoute: route, messageType: kind, encryptionEpoch: null, payload: new Uint8Array(size).fill(23),
})

function changed(encoded: Uint8Array, changes: Record<number, CborValue>): Uint8Array {
  const value = assertCanonicalCbor(encoded)
  if (!Array.isArray(value)) throw new Error('TEST_DESCRIPTOR_REQUIRED')
  const fields: CborValue[] = [...value]
  for (const [index, field] of Object.entries(changes)) fields[Number(index)] = field
  return encodeCanonicalCbor(fields)
}

describe('authenticated ledger descriptor and detached envelope boundary', () => {
  it('keeps a large application envelope out of the ordered descriptor', async () => {
    const body = candidate(512 * 1024)
    const prepared = await createLedgerRecord(body)
    expect(prepared.recordBytes.length).toBeLessThan(256)
    expect(prepared.record).toEqual({ kind: 'candidate', groupRoute: route, encryptionEpoch: epoch,
      payloadHash: bytesToHex(await sha256(body)), payloadLength: body.length, inlinePayload: null })
    expect(prepared.detachedPayload).toEqual(body)
    expect(decodeLedgerRecord(prepared.recordBytes)).toEqual(prepared.record)
    const fetch = vi.fn(async () => prepared.detachedPayload)
    expect(await resolveLedgerPayload(prepared.record, fetch)).toEqual(body)
    expect(fetch).toHaveBeenCalledExactlyOnceWith(prepared.record.payloadHash)
  })

  it.each(['capability', 'epoch-manifest'] as const)('validates %s inline without fetching any application payload', async (kind) => {
    const body = control(kind)
    const prepared = await createLedgerRecord(body)
    expect(prepared.detachedPayload).toBeNull()
    expect(prepared.record.inlinePayload).toEqual(body)
    const fetch = vi.fn(async (): Promise<Uint8Array | null> => { throw new Error('MUST_NOT_FETCH') })
    expect(await resolveLedgerPayload(decodeLedgerRecord(prepared.recordBytes), fetch)).toEqual(body)
    expect(fetch).not.toHaveBeenCalled()
  })

  it('authenticates a complete descriptor chain while application bytes remain unavailable', async () => {
    const identity = await generateEd25519KeyPair()
    const configuration = { kind: 'coordinated' as const, historyId: 'h_0123456789abcdef0123456789abcdef',
      groupId: new Uint8Array(32).fill(1), genesisDigest: new Uint8Array(32).fill(2),
      executionManifestDigest: new Uint8Array(32).fill(3), authorityPublicKey: identity.publicKeyBytes }
    const log = await ReferenceRecordLog.open(configuration.historyId, new MemoryOperationStore())
    const prepared = await Promise.all([createLedgerRecord(candidate(512 * 1024)), createLedgerRecord(control('capability'))])
    const first = await log.append(prepared[0].recordBytes)
    const second = await log.append(prepared[1].recordBytes)
    const authority = createPrefixAuthority({ configuration, identity, readHead: () => log.head() })
    const verifier = await SignedInclusionFinalityProvider.open(configuration, new MemoryOperationStore())
    await verifier.ingest({ kind: 'prefix-certificate', certificate: await authority.certify() })
    await verifier.ingest({ kind: 'ordered-entry', entry: first })
    // Omitting an inline governance record cannot yield the certified prefix.
    expect(verifier.progress.finalThrough).toBe(0)
    await verifier.ingest({ kind: 'ordered-entry', entry: second })
    expect(verifier.progress.finalThrough).toBe(2)
    expect(verifier.entries().map(entry => decodeLedgerRecord(entry.bytes).kind)).toEqual(['candidate', 'capability'])
    await expect(resolveLedgerPayload(prepared[0].record, async () => null)).rejects.toThrow('LEDGER_PAYLOAD_UNAVAILABLE')
    // Availability is separate from authenticated ordering; it cannot erase a header.
    expect(verifier.progress.finalThrough).toBe(2)
  })

  it('rejects missing, truncated and corrupt detached bytes distinctly', async () => {
    const body = candidate(), prepared = await createLedgerRecord(body)
    await expect(resolveLedgerPayload(prepared.record, async () => null)).rejects.toThrow('LEDGER_PAYLOAD_UNAVAILABLE')
    await expect(verifyLedgerPayload(prepared.record, body.slice(1))).rejects.toThrow('LEDGER_PAYLOAD_LENGTH_INVALID')
    const corrupt = body.slice(); corrupt[corrupt.length - 1]! ^= 1
    await expect(verifyLedgerPayload(prepared.record, corrupt)).rejects.toThrow('LEDGER_PAYLOAD_DIGEST_MISMATCH')
    const providerError = new Error('disk unavailable')
    await expect(resolveLedgerPayload(prepared.record, async () => { throw providerError })).rejects.toBe(providerError)
  })

  it.each([
    ['route', 3, new Uint8Array(32).fill(8)],
    ['epoch', 4, encodeCanonicalCbor(43n)],
    ['cleartext epoch', 4, null],
  ] as const)('rejects a valid payload hash paired with the wrong %s', async (_label, field, value) => {
    const body = candidate(), prepared = await createLedgerRecord(body)
    const record = decodeLedgerRecord(changed(prepared.recordBytes, { [field]: value }))
    await expect(verifyLedgerPayload(record, body)).rejects.toThrow('LEDGER_PAYLOAD_METADATA_MISMATCH')
  })

  it('never promotes a fetched candidate body into a governance operation', async () => {
    const body = control('capability'), prepared = await createLedgerRecord(body)
    const misleading = decodeLedgerRecord(changed(prepared.recordBytes, { 2: 'candidate', 7: null }))
    expect(misleading.kind).toBe('candidate')
    expect(misleading.inlinePayload).toBeNull()
    await expect(resolveLedgerPayload(misleading, async () => body)).rejects.toThrow('LEDGER_PAYLOAD_METADATA_MISMATCH')
  })

  it('rejects candidate bytes hidden inside an inline governance descriptor', async () => {
    const body = encodeEnvelope({ groupRoute: route, messageType: 'candidate', encryptionEpoch: null, payload: new Uint8Array([1]) })
    const prepared = await createLedgerRecord(body)
    expect(() => decodeLedgerRecord(changed(prepared.recordBytes, { 2: 'capability', 7: body })))
      .toThrow('LEDGER_PAYLOAD_METADATA_MISMATCH')
    const capability = await createLedgerRecord(control('capability'))
    expect(() => decodeLedgerRecord(changed(capability.recordBytes, { 2: 'epoch-manifest' })))
      .toThrow('LEDGER_PAYLOAD_METADATA_MISMATCH')
  })

  it('enforces inline classification, bounded hashes, lengths and strict descriptor shape', async () => {
    const app = await createLedgerRecord(candidate()), cap = await createLedgerRecord(control('capability'))
    for (const changes of [{ 0: 2n }, { 1: 'other-domain' }, { 2: 'attestation' }, { 3: new Uint8Array(31) },
      { 4: new Uint8Array(33) }, { 5: '00' }, { 5: 'A'.repeat(64) }, { 6: 0n }, { 6: BigInt(MAX_LEDGER_PAYLOAD_BYTES) + 1n },
      { 7: app.detachedPayload! }, { 8: null }]) {
      expect(() => decodeLedgerRecord(changed(app.recordBytes, changes))).toThrow(/LEDGER_/u)
    }
    expect(() => decodeLedgerRecord(changed(cap.recordBytes, { 7: null }))).toThrow('LEDGER_PAYLOAD_INLINE_INVALID')
    expect(() => decodeLedgerRecord(changed(cap.recordBytes, { 4: epoch }))).toThrow('LEDGER_PAYLOAD_METADATA_MISMATCH')
    expect(() => decodeLedgerRecord(changed(cap.recordBytes, { 5: '00'.repeat(32) }))).toThrow('LEDGER_PAYLOAD_DIGEST_MISMATCH')
    expect(() => decodeLedgerRecord(candidate())).toThrow('LEDGER_RECORD_INVALID')
    const heartbeat = encodeEnvelope({ groupRoute: route, messageType: 'heartbeat', encryptionEpoch: null, payload: new Uint8Array([1]) })
    await expect(createLedgerRecord(heartbeat)).rejects.toThrow('LEDGER_KIND_UNSUPPORTED')
  })

  it('fails explicitly at the payload and inline-control byte limits', async () => {
    await expect(createLedgerRecord(candidate(MAX_LEDGER_PAYLOAD_BYTES))).rejects.toThrow('LEDGER_PAYLOAD_TOO_LARGE')
    await expect(createLedgerRecord(control('epoch-manifest', MAX_LEDGER_INLINE_PAYLOAD_BYTES))).rejects.toThrow('LEDGER_CONTROL_TOO_LARGE')
    const nearBound = await createLedgerRecord(control('epoch-manifest', MAX_LEDGER_INLINE_PAYLOAD_BYTES - 64))
    expect(nearBound.recordBytes.length).toBeLessThan(MAX_LEDGER_RECORD_BYTES)
    expect(decodeLedgerRecord(nearBound.recordBytes)).toEqual(nearBound.record)
    expect(() => decodeLedgerRecord(new Uint8Array(MAX_LEDGER_RECORD_BYTES + 1))).toThrow('LEDGER_RECORD_TOO_LARGE')
  })

  it('owns input bytes and descriptor metadata across asynchronous hashing and fetching', async () => {
    const input = Buffer.from(candidate()), original = new Uint8Array(input)
    const pending = createLedgerRecord(input)
    input.fill(0)
    const prepared = await pending
    expect(prepared.detachedPayload).toEqual(original)
    let release!: (value: Uint8Array) => void
    const fetched = new Promise<Uint8Array>(resolve => { release = resolve })
    const result = resolveLedgerPayload(prepared.record, async () => fetched)
    prepared.record.groupRoute.fill(0)
    prepared.record.encryptionEpoch!.fill(0)
    Object.assign(prepared.record, { payloadHash: '00'.repeat(32), payloadLength: 1 })
    release(original)
    expect(await result).toEqual(original)
    const decoded = decodeLedgerRecord(prepared.recordBytes)
    expect(decoded.groupRoute).toEqual(route)
  })

  it('validates public record objects before trusting inline data or calling a provider', async () => {
    const prepared = await createLedgerRecord(control('epoch-manifest'))
    const malformed = { ...prepared.record, inlinePayload: null } as unknown as LedgerRecord
    const fetch = vi.fn(async () => null)
    await expect(resolveLedgerPayload(malformed, fetch)).rejects.toThrow('LEDGER_PAYLOAD_INLINE_INVALID')
    expect(fetch).not.toHaveBeenCalled()
  })
})
