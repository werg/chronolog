import { afterEach, vi } from 'vitest'
import { assertCanonicalCbor, encodeCanonicalCbor } from '@chronolog/protocol'
import { decodePeerValue, encodePeerValue, type ParticipantRequest } from '@chronolog/peer-generation'
import type { FramedPeerConnection } from '@chronolog/records'
import { ApplicationSecureChannel } from './secure-channel.js'

type Packet = { readonly kind: string; readonly message?: ParticipantRequest }
type Inspect = (packet: Packet, bytes: number) => Packet | void | Promise<Packet | void>
const observers = new Map<string, Inspect>()
let restore: (() => void) | undefined
afterEach(() => { restore?.(); restore = undefined; observers.clear() })

/** A malicious/observed participant, before encryption; the relay cannot inspect or rewrite these messages. */
export function observePeerWire(identity: string, inspect: Inspect): void {
  observers.set(identity, inspect)
  if (restore !== undefined) return
  // eslint-disable-next-line @typescript-eslint/unbound-method -- The replacement supplies its actual channel through call().
  const original = ApplicationSecureChannel.prototype.prepare
  const spy = vi.spyOn(ApplicationSecureChannel.prototype, 'prepare').mockImplementation(async function (this: ApplicationSecureChannel, peerKey, sender, receiver) {
    const result = await original.call(this, peerKey, sender, receiver)
    const inspect = observers.get((sender as { readonly author: string }).author)
    if (inspect !== undefined) {
      const framed = intercept({ ...this.connection }, inspect)
      this.connection.send = (frame, options) => framed.send(frame, options)
    }
    return result
  })
  restore = () => spy.mockRestore()
}

/** Observe the actual serialized fragment boundary, retaining its ordering and backpressure. */
function intercept(connection: FramedPeerConnection, inspect: Inspect): FramedPeerConnection {
  let assembled: Uint8Array | undefined
  return { ...connection, async send(frame, options) {
    const value = assertCanonicalCbor(frame)
    if (!Array.isArray(value) || value.length !== 5 || !(value[4] instanceof Uint8Array)) throw new Error('TEST_FRAGMENT_INVALID')
    const offset = Number(value[2]), total = Number(value[3]), chunk = value[4]
    if (offset === 0) assembled = new Uint8Array(total)
    if (assembled === undefined) throw new Error('TEST_FRAGMENT_ORDER')
    assembled.set(chunk, offset)
    if (offset + chunk.length === total) {
      const result = await inspect(decodePeerValue<Packet>(assembled), total)
      assembled = undefined
      if (result !== undefined) {
        if (offset !== 0) throw new Error('TEST_REWRITE_REQUIRES_ONE_FRAGMENT')
        const bytes = encodePeerValue(result)
        frame = encodeCanonicalCbor([value[0]!, value[1]!, 0n, BigInt(bytes.length), bytes])
      }
    }
    await connection.send(frame, options)
  } }
}
