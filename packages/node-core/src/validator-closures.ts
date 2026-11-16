import {
  assertCanonicalCbor, bytesToHex, decodeEnvelope, decodeValidatorAttestation,
  encodeCanonicalCbor, encodeEnvelope, equalBytes, type Ed25519KeyPair,
} from '@chronolog/protocol'
import type { ChronologTransport, TransportRecord } from '@chronolog/records'

import { encodeSignedGovernanceClosure, signGovernanceClosure } from './governance-activation.js'
import { DurableOperationJournal, type DurableOperationStore } from './operations.js'
import type { EnvelopeCipher, EnvelopeCipherResolver } from './types.js'
import { decodeSignedEnvelope, WIRE_ENCRYPTION_EPOCH_UNAVAILABLE } from './wire.js'

interface ValidatorRevisionClosureOptions {
    readonly groupId: Uint8Array
    readonly groupRoute: Uint8Array
    readonly identity: Ed25519KeyPair
    readonly transport: ChronologTransport
    readonly store: DurableOperationStore
    readonly cipher?: EnvelopeCipher | EnvelopeCipherResolver
}

/** Durable validator promises, serialized by the node's admission-signing lock. */
export class ValidatorRevisionClosures {
  readonly #options: ValidatorRevisionClosureOptions
  readonly #journal: DurableOperationJournal
  readonly #key: string
  readonly #closed = new Map<string, Uint8Array>()
  #loaded: Promise<void> | undefined

  constructor(options: ValidatorRevisionClosureOptions) {
    this.#options = options
    this.#key = `validator-closures/${bytesToHex(options.groupId)}/${bytesToHex(options.identity.publicKeyBytes)}`
    this.#journal = new DurableOperationJournal(options.store, `${this.#key}/publication`)
  }

  isClosed(revision: Uint8Array): boolean { return this.#closed.has(bytesToHex(revision)) }

  async load(): Promise<void> {
    this.#loaded ??= (async () => {
      const saved = await this.#options.store.get(`${this.#key}/closed`)
      if (saved === null) return
      const value = assertCanonicalCbor(saved)
      if (!(value instanceof Map)) throw new Error('VALIDATOR_CLOSURE_STORE_INVALID')
      for (const [key, next] of value) {
        if (typeof key !== 'string' || !(next instanceof Uint8Array) || next.length !== 32) throw new Error('VALIDATOR_CLOSURE_STORE_INVALID')
        this.#closed.set(key, next)
      }
    })()
    await this.#loaded
  }

  async recover(): Promise<void> {
    await this.load()
    await this.#journal.recover(async (bytes) => { await this.#publish(bytes) })
  }

  async close(previous: Uint8Array, next: Uint8Array, validatorCapability: Uint8Array, now: bigint): Promise<TransportRecord> {
    await this.load()
    const key = bytesToHex(previous)
    const existing = this.#closed.get(key)
    if (existing !== undefined && !equalBytes(existing, next)) throw new Error('VALIDATOR_CLOSURE_SUCCESSOR_CONFLICT')
    const bytes = await this.#journal.run({
      operationId: key, fingerprint: encodeCanonicalCbor([previous, next, validatorCapability]),
      prepare: async () => {
        let throughMs = now < 0n ? 0n : now
        let lastAdmissionSequence = 0n
        for (const record of await this.#options.transport.history()) {
          if (record.author !== this.#options.transport.identity) continue
          try {
            const envelope = decodeEnvelope(record.payload)
            if (envelope.messageType !== 'attestation' || !equalBytes(envelope.groupRoute, this.#options.groupRoute)) continue
            const wire = await decodeSignedEnvelope(record.payload, this.#options.groupRoute, this.#options.cipher)
            const admission = decodeValidatorAttestation(wire.payload)
            if (!equalBytes(admission.membershipRevision, previous) ||
                !equalBytes(admission.groupId, this.#options.groupId) ||
                !equalBytes(admission.validatorId, this.#options.identity.publicKeyBytes) ||
                !equalBytes(wire.signer, this.#options.identity.publicKeyBytes) ||
                !equalBytes(admission.validatorCapability, validatorCapability)) continue
            if (record.sequence > lastAdmissionSequence) lastAdmissionSequence = record.sequence
            if (admission.authorTimestampMs > throughMs) throughMs = admission.authorTimestampMs
          } catch (error) {
            if (error instanceof Error && error.message === WIRE_ENCRYPTION_EPOCH_UNAVAILABLE) throw error
            if (!(error instanceof Error) || (error.name !== 'ChronologWireError' && error.name !== 'ProtocolError')) throw error
          }
        }
        const closed = new Map(this.#closed)
        closed.set(key, next.slice())
        // This promise becomes durable before a closure signature can escape.
        await this.#options.store.put(`${this.#key}/closed`, encodeCanonicalCbor(closed))
        this.#closed.set(key, next.slice())
        const signed = await signGovernanceClosure({
          groupId: this.#options.groupId, membershipRevision: previous,
          nextMembershipRevision: next, validatorId: this.#options.identity.publicKeyBytes,
          validatorCapability, throughMs, lastAdmissionSequence,
        }, this.#options.identity.privateKey)
        return encodeEnvelope({ groupRoute: this.#options.groupRoute, messageType: 'proof-bundle',
          encryptionEpoch: null, payload: encodeSignedGovernanceClosure(signed) })
      },
      apply: async (payload) => { await this.#publish(payload) },
    })
    return this.#publish(bytes)
  }

  async #publish(bytes: Uint8Array): Promise<TransportRecord> {
    const existing = (await this.#options.transport.history()).find((record) =>
      record.author === this.#options.transport.identity && equalBytes(record.payload, bytes))
    if (existing !== undefined) {
      await this.#options.transport.ensurePublished?.(existing)
      return existing
    }
    return this.#options.transport.publish(bytes)
  }
}
