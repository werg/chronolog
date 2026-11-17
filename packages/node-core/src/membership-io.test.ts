import { generateEd25519KeyPair } from '@chronolog/protocol'
import { describe, expect, it, vi } from 'vitest'

import { provisionMembership } from './membership.js'
import { createMembershipLedgerClient, MAX_MEMBERSHIP_BODY_FRAGMENTS, MAX_MEMBERSHIP_LEDGER_BYTES, readMembershipLedgerBody } from './membership-wire.js'
import { MemoryOperationStore } from './operations.js'

describe('bounded membership I/O', () => {
  it('preserves exact bytes across body fragments', async () => {
    const body = new ReadableStream<Uint8Array>({ start(controller) {
      controller.enqueue(Uint8Array.of(0, 255)); controller.enqueue(Uint8Array.of(1, 2, 3)); controller.close()
    } })
    expect(await readMembershipLedgerBody(new Response(body))).toEqual(Uint8Array.of(0, 255, 1, 2, 3))
  })

  it('bounds empty fragment floods independently of total bytes', async () => {
    let fragments = 0
    const cancel = vi.fn()
    const body = new ReadableStream<Uint8Array>({ pull(controller) { fragments++; controller.enqueue(new Uint8Array()) }, cancel })
    await expect(readMembershipLedgerBody(new Response(body))).rejects.toThrow('MEMBERSHIP_BODY_TOO_LARGE')
    expect(fragments).toBeLessThanOrEqual(MAX_MEMBERSHIP_BODY_FRAGMENTS + 2)
    expect(cancel).toHaveBeenCalledTimes(1)
  })

  it('cancels oversized declarations before consuming their bodies', async () => {
    const cancel = vi.fn(), response = new Response(new ReadableStream<Uint8Array>({ cancel }),
      { headers: { 'Content-Length': String(MAX_MEMBERSHIP_LEDGER_BYTES + 1) } })
    await expect(readMembershipLedgerBody(response)).rejects.toThrow('MEMBERSHIP_BODY_TOO_LARGE')
    expect(cancel).toHaveBeenCalledTimes(1)
  })

  it('times out a partial body even when stream cancellation never settles', async () => {
    const cancel = vi.fn(() => new Promise<void>(() => undefined))
    const response = new Response(new ReadableStream<Uint8Array>({ start(controller) { controller.enqueue(Uint8Array.of(7)) }, cancel }))
    await expect(readMembershipLedgerBody(response, { timeoutMs: 20 })).rejects.toThrow('MEMBERSHIP_IO_TIMEOUT')
    expect(cancel).toHaveBeenCalledTimes(1)
  })

  it('never treats cancellation as successful completion of a partial request', async () => {
    const controller = new AbortController(), cancel = vi.fn()
    const body = new ReadableStream<Uint8Array>({ start(stream) { stream.enqueue(Uint8Array.of(7)) }, cancel })
    const reading = readMembershipLedgerBody(new Response(body), { signal: controller.signal })
    const rejected = expect(reading).rejects.toThrow('participant operation stopped')
    await Promise.resolve(); controller.abort(new Error('participant operation stopped'))
    await rejected
    expect(cancel).toHaveBeenCalledTimes(1)
  })

  it('bounds a client whose fetch adapter ignores cancellation and retires its late body', async () => {
    const key = await generateEd25519KeyPair()
    const { descriptor, identity } = await provisionMembership({ store: new MemoryOperationStore(),
      executionManifestDigest: new Uint8Array(32).fill(1), schemaAdministratorPublicKey: key.publicKeyBytes,
      nativeAuthority: { historyId: 'h_0123456789abcdef0123456789abcdef', publicKey: key.publicKeyBytes } })
    let release!: (response: Response) => void, started!: () => void
    const requested = new Promise<void>(resolve => { started = resolve })
    const fetcher: typeof fetch = async (_url, init) => {
      expect(init).toMatchObject({ redirect: 'error', credentials: 'omit' })
      started(); return new Promise<Response>(resolve => { release = resolve })
    }
    const client = createMembershipLedgerClient({ url: 'https://resident.example/_chronolog/membership', descriptor, identity, fetch: fetcher, timeoutMs: 20 })
    const reading = client.read({ after: 0, limit: 128 })
    const rejected = expect(reading).rejects.toThrow('MEMBERSHIP_IO_TIMEOUT')
    await requested; await rejected
    const cancel = vi.fn()
    release(new Response(new ReadableStream<Uint8Array>({ cancel })))
    await Promise.resolve(); await Promise.resolve(); await Promise.resolve()
    expect(cancel).toHaveBeenCalledTimes(1)
  })
})
