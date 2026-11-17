import { MemoryOperationStore } from '@chronolog/node-core'
import { decodeOrderingEvidence, verifyPrefixCertificate } from '@chronolog/node-core/history'
import { createLedgerRecord } from '@chronolog/node-core/ledger'
import { decodeFinalityClosureRecord } from '@chronolog/node-core/finality'
import {
  MAX_MEMBERSHIP_LEDGER_BYTES, decodeMembershipLedgerResponse, provisionMembership, signMembershipLedgerRequest, encodeFinalizedControl,
  type MembershipLedgerRequest,
} from '@chronolog/node-core/membership'
import { assertCanonicalCbor, encodeCanonicalCbor, encodeEnvelope, generateEd25519KeyPair } from '@chronolog/protocol'
import { describe, expect, it, vi } from 'vitest'

import { NativeAuthority } from './authority.js'
import { createMembershipLedgerHandler, MAX_MEMBERSHIP_PAGE_ENTRY_BYTES } from './membership-http.js'

async function setup() {
  const native = await generateEd25519KeyPair(), store = new MemoryOperationStore()
  const provision = { store: new MemoryOperationStore(), executionManifestDigest: new Uint8Array(32).fill(1),
    nativeAuthority: { historyId: 'h_0123456789abcdef0123456789abcdef', publicKey: native.publicKeyBytes },
    schemaAdministratorPublicKey: native.publicKeyBytes }
  const { descriptor, identity } = await provisionMembership(provision)
  if (descriptor.history.kind !== 'coordinated') throw new Error('COORDINATED_FIXTURE_REQUIRED')
  const authority = await NativeAuthority.open({ configuration: descriptor.history, identity: native, store, now: () => 1_000, cutoffLagMs: 0 })
  const control = (value: number, size = 8) => createLedgerRecord(encodeEnvelope({ groupRoute: descriptor.groupRoute,
    messageType: 'capability', encryptionEpoch: null, payload: new Uint8Array(size).fill(value) }))
  const signed = async (request: MembershipLedgerRequest, now = 1_000) => signMembershipLedgerRequest({ descriptor, identity, request, now })
  return { native, store, descriptor, identity, authority, control, signed }
}

function request(bytes: Uint8Array, suffix = ''): Request {
  return new Request(`http://localhost/_chronolog/membership${suffix}`, { method: 'POST',
    headers: { 'content-type': 'application/cbor' }, body: bytes.slice().buffer })
}

describe('signed native membership HTTP handler', () => {
  it('times out incomplete request bodies without blocking later participant operations', async () => {
    const f = await setup(), cancel = vi.fn(() => new Promise<void>(() => undefined))
    const handler = createMembershipLedgerHandler({ authority: f.authority, descriptor: f.descriptor, now: () => 1_000, bodyTimeoutMs: 20 })
    const body = new ReadableStream<Uint8Array>({ start(stream) { stream.enqueue(Uint8Array.of(1)) }, cancel })
    const input = new Request('http://localhost/_chronolog/membership', { method: 'POST', headers: { 'Content-Type': 'application/cbor' },
      ...{ body, duplex: 'half' } })
    expect((await handler(input)).status).toBe(408)
    expect(cancel).toHaveBeenCalledTimes(1)
    expect((await handler(request(await f.signed({ kind: 'read', after: 0, limit: 128 })))).status).toBe(200)
  })

  it('serves a constant compact checkpoint without application descriptors or ciphertext', async () => {
    const f = await setup(), mirrored: Uint8Array[] = []
    expect(f.native.publicKeyBytes).not.toEqual(f.identity.publicKeyBytes)
    const body = encodeEnvelope({ groupRoute: f.descriptor.groupRoute, messageType: 'candidate',
      encryptionEpoch: encodeCanonicalCbor(0n), payload: new Uint8Array(768 * 1024).fill(42) })
    await f.authority.append(body)
    const fetchPayload = vi.spyOn(f.authority, 'getPayload')
    const handler = createMembershipLedgerHandler({ authority: f.authority, descriptor: f.descriptor, now: () => 1_000,
      sink: { putEvidence: async bytes => { mirrored.push(bytes) } } })
    const response = await handler(request(await f.signed({ kind: 'read', after: 0, limit: 128 })))
    expect(response.status).toBe(200)
    const bytes = new Uint8Array(await response.arrayBuffer())
    expect(bytes.length).toBeLessThan(2_048)
    const page = decodeMembershipLedgerResponse(bytes, 'read')
    expect(page.entries).toHaveLength(0)
    expect(page.hasMore).toBe(false)
    expect(decodeFinalityClosureRecord(page.checkpoint!.bytes)).toMatchObject({ closedThroughMs: 1_000n,
      includedHead: { position: 1 }, control: { count: 0 } })
    await verifyPrefixCertificate(page.certificate, f.authority.configuration)
    expect(fetchPayload).not.toHaveBeenCalled()
    expect(mirrored.map(decodeOrderingEvidence).map(item => item.kind)).toEqual(['ordered-entry', 'ordered-entry', 'prefix-certificate'])
  })

  it('recovers an interrupted post-commit delivery with exact retry identity and a subsequent range read', async () => {
    const f = await setup(), mirrored: Uint8Array[] = []
    let fail = true
    const sink = { putEvidence: async (bytes: Uint8Array) => {
      if (fail) { fail = false; throw new Error('delivery interrupted') }
      mirrored.push(bytes)
    } }
    let handler = createMembershipLedgerHandler({ authority: f.authority, descriptor: f.descriptor, sink, now: () => 1_000 })
    const control = await f.control(1), append = await f.signed({ kind: 'append', recordBytes: control.recordBytes })
    expect((await handler(request(append))).status).toBe(503)
    expect((await f.authority.head()).position).toBe(2)
    const reopened = await NativeAuthority.open({ configuration: f.authority.configuration, identity: f.native, store: f.store, now: () => 1_000, cutoffLagMs: 0 })
    handler = createMembershipLedgerHandler({ authority: reopened, descriptor: f.descriptor, sink, now: () => 1_000 })
    const retry = await handler(request(append))
    const entry = decodeMembershipLedgerResponse(new Uint8Array(await retry.arrayBuffer()), 'append')
    expect(entry.position).toBe(1)
    expect(entry.bytes).toEqual(control.recordBytes)
    expect((await reopened.head()).position).toBe(2)
    fail = true
    const second = await f.control(2)
    expect((await handler(request(await f.signed({ kind: 'append', recordBytes: second.recordBytes })))).status).toBe(503)
    mirrored.length = 0
    const read = await handler(request(await f.signed({ kind: 'read', after: 2, limit: 2 })))
    expect(read.status).toBe(200)
    const healed = mirrored.map(decodeOrderingEvidence)
    expect(healed).toHaveLength(3)
    expect(healed[0]).toMatchObject({ kind: 'ordered-entry', entry: { position: 3, bytes: second.recordBytes } })
    expect(healed[1]).toMatchObject({ kind: 'ordered-entry', entry: { position: 4 } })
    expect(healed[2]).toMatchObject({ kind: 'prefix-certificate', certificate: { position: 4 } })
  })

  it('requires the pinned root signature, configuration, expiry and inline control classification', async () => {
    const f = await setup()
    const handler = createMembershipLedgerHandler({ authority: f.authority, descriptor: f.descriptor, now: () => 1_000 })
    const read = await f.signed({ kind: 'read', after: 0, limit: 1 }), value = assertCanonicalCbor(read)
    if (!Array.isArray(value) || !(value[0] instanceof Uint8Array) || !(value[1] instanceof Uint8Array)) throw new Error('INVALID_TEST_WIRE')
    value[1][0] = value[1][0]! ^ 1
    expect((await handler(request(encodeCanonicalCbor(value)))).status).toBe(403)
    const expired = createMembershipLedgerHandler({ authority: f.authority, descriptor: f.descriptor, now: () => 61_001 })
    expect((await expired(request(read))).status).toBe(403)
    const other = structuredClone(f.descriptor)
    if (other.history.kind !== 'coordinated') throw new Error('COORDINATED_FIXTURE_REQUIRED')
    other.history.executionManifestDigest[0] = 9
    expect(() => createMembershipLedgerHandler({ authority: f.authority, descriptor: other })).toThrow('MEMBERSHIP_AUTHORITY_CONFIGURATION_MISMATCH')
    const wrongConfig = await signMembershipLedgerRequest({ descriptor: other, identity: f.identity,
      request: { kind: 'read', after: 0, limit: 1 }, now: 1_000 })
    expect((await handler(request(wrongConfig))).status).toBe(403)
    const application = await createLedgerRecord(encodeEnvelope({ groupRoute: f.descriptor.groupRoute, messageType: 'candidate',
      encryptionEpoch: encodeCanonicalCbor(0n), payload: new Uint8Array([1]) }))
    const control = await f.control(1)
    const wire = assertCanonicalCbor(await f.signed({ kind: 'append', recordBytes: control.recordBytes }))
    if (!Array.isArray(wire) || !(wire[0] instanceof Uint8Array)) throw new Error('INVALID_TEST_WIRE')
    const fields = assertCanonicalCbor(wire[0])
    if (!Array.isArray(fields)) throw new Error('INVALID_TEST_WIRE')
    fields[8] = application.recordBytes
    const payload = encodeCanonicalCbor(fields)
    const signature = new Uint8Array(await crypto.subtle.sign('Ed25519', f.identity.privateKey, payload.slice().buffer))
    expect((await handler(request(encodeCanonicalCbor([payload, signature])))).status).toBe(403)
    expect((await f.authority.head()).position).toBe(0)
  })

  it('bounds large control pages while keeping a complete resumable range', async () => {
    const f = await setup()
    for (let i = 0; i < 5; i++) await f.authority.appendLedgerRecord((await f.control(i, 240 * 1024)).recordBytes)
    const handler = createMembershipLedgerHandler({ authority: f.authority, descriptor: f.descriptor, now: () => 1_000 })
    const response = await handler(request(await f.signed({ kind: 'read', after: 0, limit: 128 })))
    const bytes = new Uint8Array(await response.arrayBuffer()), first = decodeMembershipLedgerResponse(bytes, 'read')
    expect(bytes.length).toBeLessThan(MAX_MEMBERSHIP_LEDGER_BYTES)
    expect(first.entries).toHaveLength(4)
    expect(first.entries.reduce((sum, entry) => sum + encodeFinalizedControl(entry).length, 0))
      .toBeLessThanOrEqual(MAX_MEMBERSHIP_PAGE_ENTRY_BYTES)
    expect(first.hasMore).toBe(true)
    const next = await handler(request(await f.signed({ kind: 'read', after: first.entries.at(-1)!.index, limit: 128 })))
    const second = decodeMembershipLedgerResponse(new Uint8Array(await next.arrayBuffer()), 'read')
    expect(second.entries.map(entry => entry.index)).toEqual([5])
    expect(second.hasMore).toBe(false)
    expect((await handler(request(await f.signed({ kind: 'read', after: 7, limit: 1 })))).status).toBe(409)
  })

  it('rejects route aliases, non-CBOR and oversized bodies before any append', async () => {
    const f = await setup(), handler = createMembershipLedgerHandler({ authority: f.authority, descriptor: f.descriptor })
    expect((await handler(request(new Uint8Array([1]), '?alias=1'))).status).toBe(404)
    expect((await handler(new Request('http://localhost/_chronolog/membership'))).status).toBe(405)
    expect((await handler(new Request('http://localhost/_chronolog/membership', { method: 'POST', body: '{}' }))).status).toBe(415)
    expect((await handler(request(new Uint8Array(MAX_MEMBERSHIP_LEDGER_BYTES + 1)))).status).toBe(413)
    expect((await f.authority.head()).position).toBe(0)
  })
})
