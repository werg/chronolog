import { openSealedValue, sealSealedValue } from '@chronolog/crypto'
import {
  MAX_SEALED_PLAINTEXT_BYTES, base64UrlToBytes, decodeSealedEnvelope, encodeSealedContext, equalBytes, sealedOp, toSqlValue,
  type SealedContext, type SealedEnvelope, type SealedRecipient,
} from '@chronolog/protocol'
import type { SettlementConfidence } from '@chronolog/rpc'

import type {
  ChronologClient, LocalSqlQueryResponse, QueryOptions, TransactionHandle, TransactionOptions,
} from './client.js'
import type { DecodedLocalSqlValue, LocalSqlInput } from './local-sql.js'

export interface SealedReaderPolicy {
  readonly policyId: Uint8Array
  readonly table: string
  /** Opaque typed row key, resolved by SQLite from the row's stored primary-key values. */
  readonly rowKey: string
  readonly version: bigint
  readonly readers: readonly SealedRecipient[]
  readonly updatedTransactionId: string
  readonly materializedRevision: string
  /** Deleted/retargeted row generations retain ciphertext, but cannot accept new values. */
  readonly closed: boolean
}

export interface StoredSealedValue {
  readonly policyId: Uint8Array
  /** The application's mutable BLOB column containing the encoded envelope. */
  readonly slot: string
  readonly policyVersion: bigint
  readonly dataVersion: bigint
  readonly envelope: SealedEnvelope
  readonly updatedTransactionId: string
  readonly materializedRevision: string
}

export interface SetReadersInput {
  readonly table: string
  /** Actual SQL primary-key values, in declared primary-key order. */
  readonly row: readonly unknown[]
  readonly readers: readonly Uint8Array[]
  /** Create with 0 and no id; replace with the observed positive version and policy id. */
  readonly expectedVersion: bigint
  readonly expectedPolicyId?: Uint8Array
}

export interface SealedPolicyChange {
  readonly handle: TransactionHandle
  readonly id: Uint8Array
}

export interface SealedPutChange {
  readonly handle: TransactionHandle
  /** Keep this context when an application needs to require this exact encrypted version. */
  readonly context: SealedContext
}

export interface SealedPutOptions extends TransactionOptions {
  /** Reject locally rather than encrypting under a policy version different from this one. */
  readonly expectedPolicyVersion?: bigint
  /** Reject locally rather than overwriting a data version different from this one. */
  readonly expectedDataVersion?: bigint
  /**
   * Explicit development escape hatch. Published ciphertext discloses to its
   * recipient set even if a provisional policy or the put is later rejected.
   */
  readonly allowProvisionalPolicy?: boolean
}

export class SealedPolicyNotFinalError extends Error {
  readonly code = 'SEALED_POLICY_NOT_FINAL'
  constructor(readonly transactionId: string, readonly confidence: SettlementConfidence) {
    super(`Reader policy transaction ${transactionId} has no immutable accepted outcome with all required references resolved; no value was encrypted or submitted. Wait for final acceptance before sharing.`)
    this.name = 'SealedPolicyNotFinalError'
  }
}

export class SealedVersionConflictError extends Error {
  readonly code = 'SEALED_VERSION_CONFLICT'
  constructor(readonly versionKind: 'policy' | 'data', readonly expected: bigint, readonly actual: bigint) {
    super(`Sealed ${versionKind} version changed: expected ${expected}, observed ${actual}; no value was encrypted or submitted`)
    this.name = 'SealedVersionConflictError'
  }
}

/** The sealed helpers pass neither plaintext nor private keys to this node/RPC facade. */
type SealedClient = Pick<ChronologClient, 'groupId' | 'identity' | 'query' | 'transaction' | 'getSettlementEvidence'>

const POLICY_SELECT = `SELECT p.policy_id, p.tbl, p.row_key, p.version, p.updated_tx, p.closed_tx,
                             r.reader_key, r.hpke_public_key
                        FROM chronolog_reader_policies AS p
                        LEFT JOIN chronolog_policy_readers AS r ON r.policy_id = p.policy_id`

/**
 * Explicit row reader policies and client-side sealed BLOB columns. Controls
 * and ciphertext are replicated; encryption/decryption runs only in this SDK.
 * No owner, team member or root is silently included among the readers.
 */
export class SealedDataActions {
  constructor(readonly client: SealedClient) {}

  /** Register this node signer's public HPKE key. Keep the private key on the reader's device. */
  async registerKey(publicKey: Uint8Array, options?: TransactionOptions): Promise<TransactionHandle> {
    return this.client.transaction([sealedOp.registerReaderKey(publicKey)], options)
  }

  /** Owner/owning-team administration, with explicit generation and version compare-and-swap. */
  async setReaders(input: SetReadersInput, options?: TransactionOptions): Promise<SealedPolicyChange> {
    const expectedPolicyId = input.expectedPolicyId === undefined ? undefined : Uint8Array.from(input.expectedPolicyId)
    const step = sealedOp.readerPolicy({
      table: input.table, rowKey: input.row, readers: input.readers, expectedVersion: input.expectedVersion,
      ...(expectedPolicyId === undefined ? {} : { expectedPolicyId }),
    })
    const handle = await this.client.transaction([step], options)
    return { handle, id: expectedPolicyId ?? await handle.createdId(0) }
  }

  /** Read a policy generation, including a closed generation retained for historical ciphertext. */
  async policy(policyId: Uint8Array, options?: QueryOptions): Promise<SealedReaderPolicy | null> {
    const requestedPolicyId = Uint8Array.from(policyId)
    const response = await this.client.query(`${POLICY_SELECT} WHERE p.policy_id = ? ORDER BY r.reader_key`, [requestedPolicyId], options)
    const policy = readPolicy(response)
    if (policy !== null && !equalBytes(policy.policyId, requestedPolicyId)) throw new Error('SEALED_POLICY_ID_MISMATCH')
    return policy
  }

  /** Resolve an existing row using SQLite's affinity, collation and exact stored key encoding. */
  async getPolicy(table: string, row: readonly unknown[], options?: QueryOptions): Promise<SealedReaderPolicy | null> {
    const parameters = row.map(localInput)
    const metadata = await this.client.query(`SELECT t.name, c.name
      FROM chronolog_tables AS t JOIN pragma_table_info(t.name) AS c
      WHERE t.name = ? COLLATE NOCASE AND c.pk > 0 ORDER BY c.pk`, [table], options)
    if (metadata.result.truncated) throw new Error('SEALED_QUERY_TRUNCATED')
    if (metadata.result.rows.length === 0) return null
    const tableName = text(metadata.result.rows[0]![0])
    const primaryKey = metadata.result.rows.map((entry) => text(entry[1]))
    if (primaryKey.length !== parameters.length) throw new TypeError('Sealed row key must have one value per primary-key column')
    const key = `chronolog_row_key(${primaryKey.map((column) => column.toLowerCase() === 'chronolog_owner'
      ? `(SELECT key FROM chronolog_principals WHERE id = t.${identifier(column)})`
      : `t.${identifier(column)}`).join(', ')})`
    const response = await this.client.query(`${POLICY_SELECT}
      WHERE p.tbl = ? AND p.closed_tx IS NULL AND p.row_key = (
        SELECT ${key} FROM ${identifier(tableName)} AS t
         WHERE ${primaryKey.map((column) => `t.${identifier(column)} = ?`).join(' AND ')})
      ORDER BY r.reader_key`, [tableName, ...parameters], {
      ...options, atRevision: metadata.revision.materializedRevision,
    })
    return readPolicy(response)
  }

  /**
   * Encrypt to the current explicit policy snapshot and submit one CAS update.
   * The default refuses provisional policy changes before encryption. A later
   * rejected CAS cannot retract the key wraps already published in a candidate.
   */
  async put(policyId: Uint8Array, slot: string, plaintext: Uint8Array, options: SealedPutOptions = {}): Promise<SealedPutChange> {
    if (!(plaintext instanceof Uint8Array) || plaintext.length > MAX_SEALED_PLAINTEXT_BYTES) throw new TypeError('Sealed plaintext must be bytes of at most 1 MiB')
    // Buffer.slice() aliases caller memory; cleanup must only clear our own copy.
    const plaintextCopy = Uint8Array.from(plaintext)
    try {
      return await this.#putCopied(Uint8Array.from(policyId), slot, plaintextCopy, { ...options })
    } finally {
      plaintextCopy.fill(0)
    }
  }

  async #putCopied(requestedPolicyId: Uint8Array, slot: string, plaintext: Uint8Array, options: SealedPutOptions): Promise<SealedPutChange> {
    const queryOptions = options.signal === undefined ? {} : { signal: options.signal }
    const policy = await this.policy(requestedPolicyId, queryOptions)
    if (policy === null || policy.closed) throw new Error('SEALED_POLICY_UNAVAILABLE')
    if (options.expectedPolicyVersion !== undefined && options.expectedPolicyVersion !== policy.version) {
      throw new SealedVersionConflictError('policy', options.expectedPolicyVersion, policy.version)
    }
    const current = await this.get(requestedPolicyId, slot, { ...queryOptions, atRevision: policy.materializedRevision })
    const dataVersion = current?.dataVersion ?? 0n
    if (options.expectedDataVersion !== undefined && options.expectedDataVersion !== dataVersion) {
      throw new SealedVersionConflictError('data', options.expectedDataVersion, dataVersion)
    }
    if (options.allowProvisionalPolicy !== true) {
      const evidence = await this.client.getSettlementEvidence(policy.updatedTransactionId)
      if (!evidence.outcome.final || evidence.unresolvedReferences.length !== 0 ||
          evidence.outcome.outcome.type !== 'accepted') {
        throw new SealedPolicyNotFinalError(policy.updatedTransactionId, evidence.confidence)
      }
    }
    assertNotAborted(options.signal)
    const context: SealedContext = {
      groupId: groupId(this.client.groupId), policyId: Uint8Array.from(policy.policyId),
      policyVersion: policy.version, slot, dataVersion: dataVersion + 1n,
    }
    const envelope = await sealSealedValue({ context, plaintext, recipients: policy.readers })
    assertNotAborted(options.signal)
    const step = sealedOp.put({ policyId: policy.policyId, expectedPolicyVersion: policy.version, expectedDataVersion: dataVersion, slot, envelope })
    const handle = await this.client.transaction([step], {
      ...(options.signal === undefined ? {} : { signal: options.signal }),
      ...(options.idempotencyKey === undefined ? {} : { idempotencyKey: options.idempotencyKey }),
    })
    return { handle, context }
  }

  /** Read ciphertext and externally stored version metadata; this performs no decryption. */
  async get(policyId: Uint8Array, slot: string, options?: QueryOptions): Promise<StoredSealedValue | null> {
    const requestedPolicyId = Uint8Array.from(policyId)
    const response = await this.client.query(`SELECT data_version, policy_version, envelope, updated_tx
      FROM chronolog_sealed_values WHERE policy_id = ? AND slot = ?`, [requestedPolicyId, slot], options)
    if (response.result.truncated) throw new Error('SEALED_QUERY_TRUNCATED')
    const row = response.result.rows[0]
    if (row === undefined) return null
    const value: StoredSealedValue = {
      policyId: requestedPolicyId, slot, dataVersion: integer(row[0]), policyVersion: integer(row[1]),
      envelope: decodeSealedEnvelope(bytes(row[2])), updatedTransactionId: transactionId(row[3]),
      materializedRevision: response.revision.materializedRevision,
    }
    assertContext(value.envelope, this.#expectedContext(value))
    return value
  }

  /**
   * Decrypt on this client with a reader private key. Historical data uses the
   * policy version recorded with that value, not the policy's latest version.
   * Pass an expected context when the application requires an exact version.
   */
  async decrypt(
    value: StoredSealedValue,
    recipientPrivateKey: CryptoKey,
    readerId?: Uint8Array,
    expectedContext?: SealedContext,
  ): Promise<Uint8Array> {
    const expected = this.#expectedContext(value)
    if (expectedContext !== undefined && !equalBytes(encodeSealedContext(expected), encodeSealedContext(expectedContext))) {
      throw new Error('SEALED_EXPECTED_CONTEXT_MISMATCH')
    }
    return openSealedValue({
      envelope: value.envelope, expectedContext: expected,
      readerId: readerId ?? await this.client.identity(), recipientPrivateKey,
    })
  }

  #expectedContext(value: StoredSealedValue): SealedContext {
    return {
      groupId: groupId(this.client.groupId), policyId: value.policyId, policyVersion: value.policyVersion,
      slot: value.slot, dataVersion: value.dataVersion,
    }
  }
}

function readPolicy(response: LocalSqlQueryResponse): SealedReaderPolicy | null {
  if (response.result.truncated) throw new Error('SEALED_QUERY_TRUNCATED')
  const first = response.result.rows[0]
  if (first === undefined) return null
  return {
    policyId: bytes(first[0]), table: text(first[1]), rowKey: text(first[2]), version: integer(first[3]),
    updatedTransactionId: transactionId(first[4]), closed: first[5] !== null,
    readers: response.result.rows.filter((row) => row[6] !== null).map((row) => ({ readerId: bytes(row[6]), publicKey: bytes(row[7]) })),
    materializedRevision: response.revision.materializedRevision,
  }
}

function assertContext(envelope: SealedEnvelope, expected: SealedContext): void {
  if (!equalBytes(encodeSealedContext(envelope.context), encodeSealedContext(expected))) throw new Error('SEALED_EXPECTED_CONTEXT_MISMATCH')
}

function groupId(value: string): Uint8Array {
  if (!/^[A-Za-z0-9_-]+$/u.test(value)) throw new TypeError('Sealed group id must be canonical base64url')
  const decoded = base64UrlToBytes(value)
  if (decoded.length !== 32) throw new TypeError('Sealed group id must encode exactly 32 bytes')
  return decoded
}

function bytes(value: DecodedLocalSqlValue | undefined): Uint8Array {
  if (!(value instanceof Uint8Array)) throw new TypeError('Expected sealed metadata bytes')
  return Uint8Array.from(value)
}
function text(value: DecodedLocalSqlValue | undefined): string {
  if (typeof value !== 'string') throw new TypeError('Expected sealed metadata text')
  return value
}
function integer(value: DecodedLocalSqlValue | undefined): bigint {
  if (typeof value !== 'bigint' || value < 1n) throw new TypeError('Expected a positive sealed metadata version')
  return value
}
function transactionId(value: DecodedLocalSqlValue | undefined): string {
  const result = new TextDecoder('utf-8', { fatal: true }).decode(bytes(value))
  if (result.length === 0) throw new TypeError('Expected a sealed metadata transaction id')
  return result
}
function identifier(value: string): string { return `"${value.replaceAll('"', '""')}"` }
function assertNotAborted(signal?: AbortSignal): void { if (signal?.aborted === true) throw signal.reason }
function localInput(input: unknown): LocalSqlInput {
  const value = toSqlValue(input)
  switch (value.kind) {
    case 'null': return null
    case 'integer': return value.value
    case 'real': return { kind: 'real', value: value.value }
    case 'text': return value.value
    case 'blob': return Uint8Array.from(value.value)
  }
}
