import { readFile } from 'node:fs/promises'
import { join } from 'node:path'
import { randomUUID } from 'node:crypto'

import {
  ChronologClient,
  GROUP_COLLECTIVE_ID,
  platformOp,
  sqlValue,
  type ClientSqlBindings,
  type ClientSqlValue,
  type CollectiveRole,
  type GrantOperation,
  type PlatformOp,
  type SqlValue,
  type TransactionStepInput,
} from '@chronolog/client'
import { HttpRpcTransport } from '@chronolog/rpc'

interface SqlSpec {
  readonly sql: string
  readonly bindings?: readonly JsonSqlValue[] | Readonly<Record<string, JsonSqlValue>>
}
/**
 * A platform operation in JSON. Keys and ids are base64url; `group` names the
 * group collective. Row keys are primary-key values, like SQL bindings.
 *   {"platform":"grant","table":"notes","grantee":KEY,"operations":["update"],"rowKey":[1],"columns":["status"],"grantor":ID?}
 *   {"platform":"revoke_grant","grantId":ID}
 *   {"platform":"create_collective","governance":{"insert":"member","update":"member","delete":"admin"},"invitees":[KEY]}
 *   {"platform":"accept_membership","collectiveId":ID}   {"platform":"leave","collectiveId":ID}
 *   {"platform":"set_members","collectiveId":ID,"changes":[{"member":KEY,"role":"admin|member|remove"}]}
 *   {"platform":"transfer_row","table":"notes","rowKey":[1],"toOwner":ID,"carry":true,"fromOwner":ID?}
 *   {"platform":"transfer_all","toOwner":KEY,"fromOwner":ID?}
 *   {"platform":"accept_transfer","offerId":ID}
 *   {"platform":"cancel_transfer","offerId":ID}
 */
type PlatformSpec = { readonly platform: string } & Readonly<Record<string, unknown>>
interface TransactionSpec {
  readonly steps: readonly (SqlSpec | PlatformSpec)[]
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
type SeedStep =
  | { readonly sql: string; readonly bindings: readonly SeedValue[] }
  | { readonly platform: 'seed_rows'; readonly table: string; readonly columns: readonly string[]; readonly rows: readonly (readonly SeedValue[])[] }
  | { readonly platform: 'end_seeding' }
interface SeedPlan {
  readonly format: 'chronolog-fork-seed-v5'
  readonly batches: readonly {
    readonly batch: number
    readonly label: string
    readonly steps: readonly SeedStep[]
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
      const steps: TransactionSpec['steps'] = spec.steps
      if (!(steps as unknown instanceof Array) || steps.length === 0) throw new Error('Transaction spec requires steps')
      const handle = await client.transaction(
        steps.map((step): TransactionStepInput => 'platform' in step
          ? jsonPlatformOp(step)
          : { sql: step.sql, params: jsonBindings(step.bindings ?? []) }),
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
      if (plan.format !== 'chronolog-fork-seed-v5' || !(batches as unknown instanceof Array)) throw new Error('Not a fork seed plan')
      let applied = 0
      let skipped = 0
      for (const batch of batches) {
        const handle = await client.transaction(batch.steps.map((step): TransactionStepInput => {
          if ('sql' in step) return { sql: step.sql, params: step.bindings.map(seedValue) }
          if (step.platform === 'end_seeding') return platformOp.endSeeding()
          return platformOp.seedRows(step.table, step.columns, step.rows.map((row) => row.map(seedValue)))
        }))
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

function jsonPlatformOp(spec: PlatformSpec): PlatformOp {
  const text = (name: string): string => {
    const value = spec[name]
    if (typeof value !== 'string') throw new Error(`Platform step ${spec.platform} requires ${name}`)
    return value
  }
  const key = (value: unknown, name: string): Uint8Array => {
    const bytes = typeof value === 'string' ? Uint8Array.from(Buffer.from(value, 'base64url')) : new Uint8Array()
    if (bytes.length !== 32) throw new Error(`${name} must be 32 bytes of base64url`)
    return bytes
  }
  const id = (name: string): Uint8Array => {
    const value = text(name)
    return value === 'group' ? GROUP_COLLECTIVE_ID : key(value, name)
  }
  const optionalId = (name: string): Uint8Array | undefined => spec[name] === undefined ? undefined : id(name)
  const list = (name: string): readonly unknown[] => {
    const value = spec[name]
    if (!Array.isArray(value)) throw new Error(`Platform step ${spec.platform} requires a ${name} list`)
    return value
  }
  const rowKey = (): ClientSqlValue[] => list('rowKey').map(jsonValue)
  const keyList = (name: string): Uint8Array[] => list(name).map((value, index) => key(value, `${name}[${index}]`))
  switch (spec.platform) {
    case 'grant': {
      const grantor = optionalId('grantor')
      return platformOp.grant({
        table: text('table'),
        grantee: id('grantee'),
        operations: list('operations') as GrantOperation[],
        ...(grantor === undefined ? {} : { grantor }),
        ...(spec.rowKey === undefined ? {} : { rowKey: rowKey() }),
        ...(spec.columns === undefined ? {} : { columns: list('columns') as string[] }),
      })
    }
    case 'revoke_grant': return platformOp.revokeGrant(id('grantId'))
    case 'create_collective': return platformOp.createCollective({
      governance: spec.governance as { insert: CollectiveRole; update: CollectiveRole; delete: CollectiveRole },
      invitees: spec.invitees === undefined ? [] : keyList('invitees'),
    })
    case 'accept_membership': return platformOp.acceptMembership(id('collectiveId'))
    case 'leave': return platformOp.leave(id('collectiveId'))
    case 'set_members': return platformOp.setMembers(id('collectiveId'), list('changes').map((change) => {
      const entry = change as { readonly member?: unknown; readonly role?: unknown }
      if (typeof entry.member !== 'string' || (entry.role !== 'admin' && entry.role !== 'member' && entry.role !== 'remove')) {
        throw new Error('set_members changes are {"member": KEY, "role": "admin"|"member"|"remove"}')
      }
      return { member: key(entry.member, 'member'), role: entry.role }
    }))
    case 'transfer_row': {
      const fromOwner = optionalId('fromOwner')
      return platformOp.transferRow({
        table: text('table'), rowKey: rowKey(), toOwner: id('toOwner'), carry: spec.carry === true,
        ...(fromOwner === undefined ? {} : { fromOwner }),
      })
    }
    case 'transfer_all': {
      const fromOwner = optionalId('fromOwner')
      return platformOp.transferAll({ toOwner: id('toOwner'), ...(fromOwner === undefined ? {} : { fromOwner }) })
    }
    case 'accept_transfer': return platformOp.acceptTransfer(id('offerId'))
    case 'cancel_transfer': return platformOp.cancelTransfer(id('offerId'))
    default: throw new Error(`Unknown platform step: ${spec.platform}`)
  }
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
