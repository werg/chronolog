import { readFile } from 'node:fs/promises'
import { join } from 'node:path'
import { randomUUID } from 'node:crypto'

import { ChronologClient, sqlValue, type ClientSqlBindings, type ClientSqlValue, type SqlValue } from '@chronolog/client'
import { HttpRpcTransport } from '@chronolog/rpc'

interface SqlSpec {
  readonly sql: string
  readonly bindings?: readonly JsonSqlValue[] | Readonly<Record<string, JsonSqlValue>>
}
interface TransactionSpec {
  readonly statements: readonly SqlSpec[]
  readonly wait?: boolean
  readonly idempotencyKey?: string
}
/** Plain JSON values, or an explicit SQLite value such as {"kind":"integer","value":"9007199254740993"}. */
type JsonSqlValue = null | boolean | number | string | { readonly kind: string; readonly value?: unknown }
/** The positional SQLite value of a fork seed plan; a BLOB is base64url text. */
type SeedValue =
  | { readonly kind: 'null' }
  | { readonly kind: 'integer'; readonly value: string }
  | { readonly kind: 'real'; readonly value: number }
  | { readonly kind: 'text'; readonly value: string }
  | { readonly kind: 'blob'; readonly value: string }
interface SeedPlan {
  readonly format: 'chronolog-fork-seed-v2'
  readonly batches: readonly {
    readonly batch: number
    readonly label: string
    readonly statements: readonly { readonly sql: string; readonly bindings: readonly SeedValue[] }[]
  }[]
}
/** Rejection code of a seed batch whose guard found it already applied. */
const FORK_SEED_APPLIED_REJECTION = 'assert:fork_seed_applied'
interface CapabilitySpec {
  readonly subjectId: string
  readonly signingPublicKey: string
  readonly transportAuthor?: string
  readonly role: 'reader' | 'writer' | 'validator' | 'administrator'
  readonly minimumAuthorTimestampMs?: string
  readonly hpkePublicKey?: string
}

const args = process.argv.slice(2)
const command = args.shift()
if (command === undefined || command === 'help' || command === '--help') usage(command === undefined ? 1 : 0)

const defaults = await localDefaults()
const groupId = process.env.CHRONOLOG_GROUP_ID ?? defaults.groupId
if (groupId === undefined) throw new Error('Set CHRONOLOG_GROUP_ID or start chronologd with the default data directory')
const baseUrl = process.env.CHRONOLOG_URL ?? 'http://127.0.0.1:8787'
const transport = new HttpRpcTransport({
  baseUrl,
  ...(process.env.CHRONOLOG_TOKEN === undefined ? {} : { token: process.env.CHRONOLOG_TOKEN }),
})
const client = new ChronologClient({
  groupId,
  transport,
})

try {
  switch (command) {
    case 'status': output(await client.getStatus()); break
    case 'query': {
      const sql = requiredArg(args.shift(), 'query SQL [PARAMETERS_JSON]')
      const parameters = args[0] === undefined ? [] : jsonBindings(JSON.parse(args[0]))
      if (!Array.isArray(parameters)) throw new Error('Local query parameters must be a JSON array')
      output(await client.query(sql, parameters))
      break
    }
    case 'transact': {
      const spec = JSON.parse(await inlineOrFile(requiredArg(args.shift(), 'transact SPEC_JSON_OR_@FILE'))) as TransactionSpec
      const statements: readonly SqlSpec[] = spec.statements
      if (!(statements as unknown instanceof Array) || statements.length === 0) throw new Error('Transaction spec requires statements')
      const handle = await client.transaction(
        statements.map((statement) => ({ sql: statement.sql, params: jsonBindings(statement.bindings ?? []) })),
        spec.idempotencyKey === undefined ? {} : { idempotencyKey: spec.idempotencyKey },
      )
      output(spec.wait === true ? { submission: handle.submission, outcome: await waitForOutcome(handle.transactionId) } : handle.submission)
      handle.dispose()
      break
    }
    case 'outcome': output(await client.getTransactionOutcome(requiredArg(args.shift(), 'outcome TRANSACTION_ID'))); break
    case 'evidence': output(await client.getSettlementEvidence(requiredArg(args.shift(), 'evidence TRANSACTION_ID'))); break
    case 'watermark': output(await client.validatorWatermark()); break
    case 'replication': output(await client.getReplicationStatus()); break
    case 'doctor': {
      const [healthResponse, status, replication] = await Promise.all([
        fetch(`${baseUrl.replace(/\/$/u, '')}/health`),
        client.getStatus(),
        client.getReplicationStatus(),
      ])
      const health = await healthResponse.json() as { readonly ok?: unknown; readonly lastError?: unknown }
      let governance: unknown
      try { governance = await transport.unary('governance.getStatus', { groupId, requestId: randomUUID() }) }
      catch (error) { governance = { unavailable: error instanceof Error ? error.message : String(error) } }
      const checks = {
        health: healthResponse.ok && health.ok === true,
        nodeReady: status.state === 'ready' && status.writable,
        replication: replication.feedsWithGaps === 0 && replication.quarantinedFeeds.length === 0 && replication.state !== 'degraded',
        governance: typeof governance === 'object' && governance !== null && !('unavailable' in governance),
      }
      const ok = Object.values(checks).every(Boolean)
      output({ ok, checks, status, replication, governance, health })
      if (!ok) process.exitCode = 2
      break
    }
    case 'governance': {
      const operation = requiredArg(args.shift(), 'governance <status|grant|revoke|rotate|history> ...')
      const base = { groupId, requestId: randomUUID() }
      if (operation === 'status') output(await transport.unary('governance.getStatus', base))
      else if (operation === 'grant') {
        const spec = JSON.parse(await inlineOrFile(requiredArg(args.shift(), 'governance grant SPEC_JSON_OR_@FILE'))) as CapabilitySpec
        output(await transport.unary('governance.grantCapability', { ...base, ...spec }))
      } else if (operation === 'revoke') {
        if (args.length === 0) throw new Error('Usage: chronolog governance revoke CAPABILITY_ID [...]')
        output(await transport.unary('governance.revokeCapabilities', { ...base, capabilityIds: args }))
      } else if (operation === 'rotate') {
        output(await transport.unary('governance.rotateEpoch', base))
      } else if (operation === 'history') {
        output(await transport.unary('governance.grantHistoricalAccess', {
          ...base,
          subjectId: requiredArg(args.shift(), 'governance history SUBJECT_ID'),
        }))
      } else throw new Error(`Unknown governance operation: ${operation}`)
      break
    }
    case 'seed': {
      // Submits a fork seed plan (see `pnpm group fork`) one batch at a time.
      // Each batch's first statement asserts it has not been applied yet, so a
      // rerun after an interruption skips finished batches.
      const plan = JSON.parse(await inlineOrFile(requiredArg(args.shift(), 'seed @fork-seed.json'))) as SeedPlan
      const batches: SeedPlan['batches'] = plan.batches
      if (plan.format !== 'chronolog-fork-seed-v2' || !(batches as unknown instanceof Array)) throw new Error('Not a fork seed plan')
      let applied = 0
      let skipped = 0
      for (const batch of batches) {
        const handle = await client.transaction(batch.statements.map((statement) => ({
          sql: statement.sql,
          params: statement.bindings.map(seedValue),
        })))
        handle.dispose()
        const outcome = await waitForOutcome(handle.transactionId, 10 * 60_000)
        if (outcome.outcome.type === 'accepted') applied += 1
        else if (outcome.outcome.type === 'rejected' && outcome.outcome.rejection.code === FORK_SEED_APPLIED_REJECTION) skipped += 1
        else throw new Error(`Seed batch ${batch.batch} (${batch.label}) did not apply: ${JSON.stringify(outcome.outcome)}`)
        process.stderr.write(`seed ${batch.batch}/${batches.length} ${outcome.outcome.type === 'accepted' ? 'applied' : 'already applied'}: ${batch.label}\n`)
      }
      output({ seeded: true, batches: batches.length, applied, skipped })
      break
    }
    default: process.stderr.write(`Unknown command: ${command}\n`); usage(1)
  }
} finally {
  await client.close()
}

function jsonBindings(value: unknown): ClientSqlBindings {
  if (Array.isArray(value)) return value.map(jsonValue)
  if (typeof value !== 'object' || value === null) throw new Error('SQL bindings must be an array or object')
  return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, jsonValue(item)]))
}

function jsonValue(value: unknown): ClientSqlValue {
  if (value === null || typeof value === 'boolean' || typeof value === 'number' || typeof value === 'string') return value
  if (typeof value === 'object' && 'kind' in value) {
    const tagged = value as { readonly kind: unknown; readonly value?: unknown }
    if (tagged.kind === 'null') return sqlValue.null()
    if (tagged.kind === 'integer' && (typeof tagged.value === 'string' || typeof tagged.value === 'number')) return sqlValue.integer(BigInt(tagged.value))
    if (tagged.kind === 'real' && typeof tagged.value === 'number') return sqlValue.real(tagged.value)
    if (tagged.kind === 'text' && typeof tagged.value === 'string') return sqlValue.text(tagged.value)
    if (tagged.kind === 'blob' && typeof tagged.value === 'string') return sqlValue.blob(Buffer.from(tagged.value, 'base64url'))
  }
  throw new Error('Unsupported SQL binding value')
}

function seedValue(value: SeedValue): SqlValue {
  switch (value.kind) {
    case 'null': return sqlValue.null()
    case 'integer': return sqlValue.integer(BigInt(value.value))
    case 'real': return sqlValue.real(value.value)
    case 'text': return sqlValue.text(value.value)
    case 'blob': return sqlValue.blob(Buffer.from(value.value, 'base64url'))
  }
}

async function waitForOutcome(transactionId: string, timeoutMs = 30_000) {
  const deadline = Date.now() + timeoutMs
  while (true) {
    const outcome = await client.getTransactionOutcome(transactionId)
    if (outcome.outcome.type !== 'pending' || Date.now() >= deadline) return outcome
    await new Promise((resolve) => setTimeout(resolve, 100))
  }
}

async function localDefaults(): Promise<{ readonly groupId?: string }> {
  try {
    const dataDirectory = process.env.CHRONOLOG_DATA_DIR ?? '.chronolog'
    const config = JSON.parse(await readFile(join(dataDirectory, 'config.json'), 'utf8')) as { readonly groupId?: string }
    return config.groupId === undefined ? {} : { groupId: Buffer.from(config.groupId, 'base64').toString('base64url') }
  } catch { return {} }
}

async function inlineOrFile(value: string): Promise<string> { return value.startsWith('@') ? readFile(value.slice(1), 'utf8') : value }
function requiredArg(value: string | undefined, usageText: string): string { if (value === undefined) throw new Error(`Usage: chronolog ${usageText}`); return value }
function output(value: unknown): void { process.stdout.write(`${JSON.stringify(value, jsonReplacer, 2)}\n`) }
function jsonReplacer(_key: string, value: unknown): unknown {
  if (typeof value === 'bigint') return value.toString(10)
  if (value instanceof Uint8Array) return Buffer.from(value).toString('base64url')
  return value
}
function usage(code: number): never {
  process.stderr.write('Usage: chronolog <status|doctor|query|transact|outcome|evidence|watermark|replication|governance|seed> ...\n')
  process.exit(code)
}
