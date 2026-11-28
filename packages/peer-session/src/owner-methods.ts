import type { ApplicationAttachmentCapability } from './owner-types.js'
import type { ApplicationOperation } from './operation.js'
import type { ApplicationSession } from './session.js'
import type { WorkerApplicationOperation } from './worker-application.js'

/**
 * One forwarded owner method: the attachment capability it needs and whether it authors an
 * operation directly (`raw`), which an attachment restricted to named commands may not do.
 */
export interface OwnerMethodSpec {
  readonly capability: ApplicationAttachmentCapability
  readonly raw?: true
}

/**
 * The single list of `ApplicationSession` methods an owner attachment forwards as plain
 * request/response calls. The key is the wire method name and the dotted path on the session
 * (`'vaults.create'` calls `session.vaults.create`). The owner dispatcher and the
 * `WorkerApplicationSession` proxy are both generated from this table; stateful methods (views,
 * SQL branches, uploads, readers, signal streams, operation waits) are handled separately.
 */
export const OWNER_FORWARDED_METHODS = {
  simulate: { capability: 'queries' },
  topic: { capability: 'queries' },
  queryAsOf: { capability: 'queries' },
  topicLastOpId: { capability: 'queries' },
  permissions: { capability: 'queries' },
  seals: { capability: 'queries' },
  keysPolicy: { capability: 'queries' },
  keysNeedsRotation: { capability: 'queries' },
  unseal: { capability: 'queries' },
  readEvents: { capability: 'events' },
  opOutcome: { capability: 'operations' },
  inspectOperation: { capability: 'operations' },

  seal: { capability: 'commands', raw: true },
  setKeysPolicy: { capability: 'commands', raw: true },
  rotateEpoch: { capability: 'commands', raw: true },
  rotateTreeEpoch: { capability: 'commands', raw: true },
  rotateWrapKey: { capability: 'commands', raw: true },
  backfillMissingEpochBoxes: { capability: 'commands', raw: true },
  sealFor: { capability: 'commands' },
  createCompartment: { capability: 'commands', raw: true },
  setupSocialRecovery: { capability: 'commands', raw: true },
  requestSocialRecovery: { capability: 'commands', raw: true },
  approveSocialRecovery: { capability: 'commands', raw: true },
  completeSocialRecovery: { capability: 'commands', raw: true },
  updateReducers: { capability: 'commands', raw: true },
  publishRelease: { capability: 'commands', raw: true },
  installPackage: { capability: 'commands', raw: true },
  mountLog: { capability: 'commands', raw: true },

  'vaults.hasKey': { capability: 'queries' },
  'vaults.currentEpoch': { capability: 'queries' },
  'vaults.unseal': { capability: 'queries' },
  'vaults.unsealRows': { capability: 'queries' },
  'vaults.seal': { capability: 'commands' },
  'vaults.create': { capability: 'commands', raw: true },
  'vaults.addMember': { capability: 'commands', raw: true },
  'vaults.removeMember': { capability: 'commands', raw: true },

  admitMember: { capability: 'admission', raw: true },
  removeMember: { capability: 'admission', raw: true },
  admissionStatus: { capability: 'admission' },
  'admission.status': { capability: 'admission' },
  'admission.opStatus': { capability: 'admission' },
  'admission.equivocations': { capability: 'admission' },
  'admission.schedulePolicy': { capability: 'admission', raw: true },
  'admission.pinCheckpoint': { capability: 'admission', raw: true },
  'admission.pinFrontier': { capability: 'admission' },
  'admission.createCheckpoint': { capability: 'admission' },
  'admission.submitEvidence': { capability: 'admission' },
  'admission.bootstrapFromCheckpoint': { capability: 'admission' },

  diagnostics: { capability: 'diagnostics' },
  exportFacts: { capability: 'replication' },
  mergeFacts: { capability: 'replication' },
} as const satisfies Readonly<Record<string, OwnerMethodSpec>>

export type OwnerForwardedMethodName = keyof typeof OWNER_FORWARDED_METHODS
export type OwnerForwardedNamespace = OwnerForwardedMethodName extends infer K ? K extends `${infer N}.${string}` ? N : never : never

/** Maximum positional arguments of any forwarded method. */
export const OWNER_FORWARDED_MAX_ARGS = 4

/**
 * Wire form of a forwarded result. Operations cannot cross a message port, so the owner sends
 * their ids and says where they were: `self` (the result is an operation) or `field` (the
 * result's `operation` field is one). The proxy rebuilds `WorkerApplicationOperation`s there.
 */
export interface OwnerForwardedResult {
  readonly value: unknown
  readonly operation: 'self' | 'field' | null
}

type SessionMember<K extends string> =
  K extends `${infer N}.${infer M}`
    ? N extends keyof ApplicationSession ? M extends keyof ApplicationSession[N] ? ApplicationSession[N][M] : never : never
    : K extends keyof ApplicationSession ? ApplicationSession[K] : never

type Remote<T> =
  T extends ApplicationOperation ? WorkerApplicationOperation
  : T extends { readonly operation: ApplicationOperation } ? { readonly [P in keyof T]: P extends 'operation' ? WorkerApplicationOperation : T[P] }
  : T

/** The proxy signature of one forwarded method: same parameters, asynchronous remote result. */
export type ForwardedOwnerMethod<K extends OwnerForwardedMethodName> =
  SessionMember<K> extends (...args: infer A) => infer R ? (...args: A) => Promise<Remote<Awaited<R>>> : never

/** Top-level forwarded methods, keyed by session method name. */
export type ForwardedOwnerMethods = { readonly [K in OwnerForwardedMethodName as K extends `${string}.${string}` ? never : K]: ForwardedOwnerMethod<K> }

/** Forwarded methods of one session namespace (`vaults`, `admission`). */
export type ForwardedOwnerNamespace<N extends string> = { readonly [K in OwnerForwardedMethodName as K extends `${N}.${infer M}` ? M : never]: ForwardedOwnerMethod<K> }

const isOperation = (value: unknown): value is ApplicationOperation =>
  value !== null && typeof value === 'object' && typeof (value as { id?: unknown }).id === 'string' &&
  typeof (value as { operationId?: unknown }).operationId === 'string' && typeof (value as { inspect?: unknown }).inspect === 'function'

const operationIds = (operation: ApplicationOperation): { readonly id: string; readonly operationId: string } => ({ id: operation.id, operationId: operation.operationId })

/** Owner side: resolve and run one forwarded method, returning its wire result. */
export async function invokeForwardedOwnerMethod(session: ApplicationSession, method: OwnerForwardedMethodName, args: readonly unknown[]): Promise<OwnerForwardedResult> {
  const dot = method.indexOf('.')
  const target = (dot < 0 ? session : (session as unknown as Record<string, unknown>)[method.slice(0, dot)]) as Record<string, unknown>
  const fn = target[dot < 0 ? method : method.slice(dot + 1)]
  if (typeof fn !== 'function') throw new Error('ENDPOINT_METHOD_UNKNOWN')
  const value: unknown = await (fn as (...input: unknown[]) => unknown).apply(target, [...args])
  if (isOperation(value)) return { value: operationIds(value), operation: 'self' }
  if (value !== null && typeof value === 'object' && isOperation((value as { operation?: unknown }).operation)) {
    const record = value as Record<string, unknown> & { operation: ApplicationOperation }
    return { value: { ...record, operation: operationIds(record.operation) }, operation: 'field' }
  }
  return { value, operation: null }
}

export const isForwardedOwnerMethod = (method: string): method is OwnerForwardedMethodName => Object.hasOwn(OWNER_FORWARDED_METHODS, method)
