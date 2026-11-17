import { generateX25519KeyPair } from '@chronolog/crypto'
import { bytesToBase64Url, encodeSealedEnvelope, equalBytes, utf8 } from '@chronolog/protocol'
import type { SealedEnvelope, SealedPlatformOp } from '@chronolog/protocol'
import type { TransactionOutcome } from '@chronolog/rpc'

import type { LocalSqlQueryResponse, TransactionHandle } from '../../packages/client/src/client.js'
import type { DecodedLocalSqlValue } from '../../packages/client/src/local-sql.js'
import { SealedDataActions } from '../../packages/client/src/sealed.js'

// This process has no Vitest IPC. All modules are loaded before the Node-only
// global is removed, and the complete key/encrypt/read/decrypt path runs without it.
const bufferDescriptor = Object.getOwnPropertyDescriptor(globalThis, 'Buffer')!
Object.defineProperty(globalThis, 'Buffer', { value: undefined, writable: true, configurable: true })
try {
  if (typeof globalThis.Buffer !== 'undefined') throw new Error('BUFFER_MUST_BE_ABSENT')
  const bytes = (seed: number) => new Uint8Array(32).fill(seed)
  const groupId = bytesToBase64Url(bytes(1))
  const reader = await generateX25519KeyPair()
  let envelope: SealedEnvelope | undefined
  const response = (rows: readonly (readonly DecodedLocalSqlValue[])[]): LocalSqlQueryResponse => ({
    revision: { groupId, materializedRevision: '7', eventSetRevision: '9', publishedOrderLength: '3', executionManifestDigest: '',
      replaying: false, view: 'final', finalRevision: '7', finalOrderLength: '3' },
    result: { columns: [], rows, truncated: false, consensusSafe: false,
      raw: { columns: [], rows: [], truncated: false, consensusSafe: false } },
  })
  const actions = new SealedDataActions({
    groupId,
    identity: async () => bytes(4),
    query: async (sql) => {
      if (sql.includes('FROM chronolog_reader_policies')) return response([
        [bytes(2), 'notes', 'rk1:opaque', 1n, utf8('policy-tx-id'), null, bytes(4), reader.publicKeyBytes],
      ])
      if (sql.includes('FROM chronolog_sealed_values')) return response(envelope === undefined ? [] : [
        [envelope.context.dataVersion, envelope.context.policyVersion, encodeSealedEnvelope(envelope), utf8('value-tx-id')],
      ])
      throw new Error(`Unexpected query ${sql}`)
    },
    transaction: async (steps) => {
      const step = steps[0] as SealedPlatformOp
      if (step.op !== 'sealed_put') throw new Error('EXPECTED_SEALED_PUT')
      envelope = step.envelope
      return { createdId: async () => bytes(2) } as unknown as TransactionHandle
    },
    getTransactionOutcome: async (transactionId): Promise<TransactionOutcome> => ({
      transactionId, outcome: { type: 'accepted' },
      eventSetRevision: '9', materializedRevision: '7', orderKey: 'policy-order',
      changedByReplay: false, admissible: true, final: true, observedAt: '1970-01-01T00:00:00.001Z',
    }),
  })
  const plaintext = utf8('browser secret')
  const change = await actions.put(bytes(2), 'body', plaintext)
  const stored = await actions.get(bytes(2), 'body')
  if (stored === null) throw new Error('SEALED_VALUE_MISSING')
  if (stored.envelope.ciphertext.byteLength !== plaintext.byteLength + 16) throw new Error('SEALED_CIPHERTEXT_INVALID')
  const decrypted = await actions.decrypt(stored, reader.privateKey, bytes(4), change.context)
  if (!equalBytes(decrypted, plaintext)) throw new Error('SEALED_PLAINTEXT_MISMATCH')
  if (typeof globalThis.Buffer !== 'undefined') throw new Error('BUFFER_REINTRODUCED_DURING_CRYPTO')
} finally {
  Object.defineProperty(globalThis, 'Buffer', bufferDescriptor)
}
process.stdout.write('sealed-browser-globals-ok\n')
