import { readFile } from 'node:fs/promises'
import { resolve } from 'node:path'
import { pathToFileURL } from 'node:url'

import {
  DurableEffectWorker, DurableTimerScheduler, NativeFinalityService, ResidentAgentService,
} from '@chronolog/agent-service'
import type {
  AgentApplicationContext, AgentApplicationModule, FinalEventPublisher, ResidentTask,
} from '@chronolog/agent-service'
import { createGovernedPeerService } from '@chronolog/agent-service/governed-peer'
import type { CapabilitySnapshot } from '@chronolog/capabilities'
import type {
  ChronologNode, DurableOperationStore, EnrollmentDescriptor, OrderedRecordHead,
} from '@chronolog/node-core'
import { verifyEnrollmentDescriptor } from '@chronolog/node-core'
import { bytesToHex, equalBytes } from '@chronolog/protocol'
import type { Ed25519KeyPair } from '@chronolog/protocol'
import type { ChronologTransport, FeedLink } from '@chronolog/records'

export interface DaemonAgentRuntimeOptions {
  readonly node: ChronologNode
  readonly transport: ChronologTransport
  readonly store: DurableOperationStore
  readonly identity: Ed25519KeyPair
  readonly descriptor: EnrollmentDescriptor
  readonly activeMembership: () => CapabilitySnapshot
  readonly finalityRecordQuotaBytes?: number
  readonly finalityPayloadQuotaBytes?: number
  readonly finalityClock?: () => number
  readonly continuity?: OrderedRecordHead
  readonly modulePath?: string
  /** Dependency injection for native integration tests and embedded deployments. */
  readonly application?: AgentApplicationModule
  readonly peerLinks: { readonly local: FeedLink; attach(link: FeedLink): () => void }
}

export async function createDaemonAgentRuntime(options: DaemonAgentRuntimeOptions) {
  if (options.application !== undefined && options.modulePath !== undefined) throw new Error('AGENT_MODULE_DUPLICATE')
  const descriptor = structuredClone(options.descriptor)
  await verifyEnrollmentDescriptor(descriptor)
  const history = descriptor.history
  if (!equalBytes(options.node.groupId, history.groupId) || !equalBytes(options.node.identity, options.identity.publicKeyBytes) ||
      !equalBytes(options.node.executionManifestDigest, history.executionManifestDigest) ||
      options.node.historyPolicy !== history.kind) throw new Error('AGENT_REPLICA_CONFIGURATION_MISMATCH')
  const sourceId = `${bytesToHex(history.groupId)}/${history.kind === 'coordinated'
    ? history.historyId : bytesToHex(history.genesisDigest)}`
  const finality = history.kind === 'coordinated' &&
    (history.providerId ?? 'signed-inclusion-v2') === 'signed-inclusion-v2' &&
    equalBytes(history.authorityPublicKey, options.identity.publicKeyBytes)
    ? await NativeFinalityService.open({ descriptor, identity: options.identity, store: options.store,
      ...(options.finalityClock === undefined ? {} : { now: options.finalityClock }),
      ...(options.finalityRecordQuotaBytes === undefined ? {} : { recordQuotaBytes: options.finalityRecordQuotaBytes }),
      ...(options.finalityPayloadQuotaBytes === undefined ? {} : { payloadQuotaBytes: options.finalityPayloadQuotaBytes }),
      ...(options.continuity === undefined ? {} : { continuity: options.continuity }) })
    : null
  if (finality === null && options.continuity !== undefined) throw new Error('FINALITY_CONTINUITY_WITHOUT_LOCAL_PROVIDER')
  const controller = new AbortController()
  const peers = await createGovernedPeerService({ identity: options.identity, groupId: history.groupId,
    activeMembership: options.activeMembership, local: options.peerLinks.local,
    attach: (link) => options.peerLinks.attach(link) })
  const publisher: FinalEventPublisher = {
    historyProfile: 'chronological',
    publishFinal: async (topic, payload, input) => {
      // A sibling resident task can stop the authority before runtime.close().
      // Its task signal must interrupt finality waiting as well as provider work.
      const signal = input.signal === undefined ? controller.signal : AbortSignal.any([controller.signal, input.signal])
      signal.throwIfAborted()
      const transaction = await options.node.events.publish(topic, payload, { operationId: input.operationId })
      await waitForFinalAcceptance(options.node, transaction.txId, signal)
    },
  }
  const context: AgentApplicationContext = {
    node: options.node, store: options.store, finality, signals: peers.signals, publisher, sourceId,
    connectPeer: (input) => peers.connectPeer(input),
  }
  try {
    const application = options.application ?? (options.modulePath === undefined ? undefined : await loadApplicationModule(options.modulePath))
    const definition = application === undefined ? {} : await application.createAgent(context)
    const tasks: ResidentTask[] = finality === null ? [] : [{ id: 'finality', run: (signal) => finality.serve(options.transport, signal) }]
    const effects: DurableEffectWorker[] = [], timers: DurableTimerScheduler[] = []
    for (const entry of definition.effects ?? []) {
      const worker = await DurableEffectWorker.open({ sourceId, store: options.store, source: options.node.events,
        publisher, handler: entry.handler, resultTopic: entry.resultTopic })
      effects.push(worker)
      tasks.push({ id: `effect:${entry.handler.id}`, run: (signal) => worker.run(signal) })
    }
    for (const entry of definition.timers ?? []) {
      const timer = await DurableTimerScheduler.open({ sourceId, store: options.store, source: options.node.events,
        id: entry.id, configurationTopic: entry.configurationTopic, publisher: entry.publisher })
      timers.push(timer)
      tasks.push({ id: `timer:${entry.id}`, run: (signal) => timer.run(signal) })
    }
    tasks.push(...definition.tasks ?? [])
    const service = tasks.length === 0 ? null : new ResidentAgentService(tasks)
    let running: Promise<void> | null = null
    return {
      finality, effects, timers, context,
      get taskIds() { return tasks.map((task) => task.id) },
      get status() { return service?.status ?? { running: false, failedTask: null } },
      run(): Promise<void> {
        if (running !== null) throw new Error('AGENT_SERVICE_ALREADY_RUNNING')
        if (controller.signal.aborted) throw new Error('AGENT_SERVICE_STOPPED')
        running = (service?.run(controller.signal) ?? Promise.resolve()).catch(async (error: unknown) => {
          controller.abort(error)
          await peers.close().catch(() => undefined)
          throw error
        })
        return running
      },
      async close(): Promise<void> {
        controller.abort()
        await peers.close()
        if (running !== null) await running.catch(() => undefined)
      },
    }
  } catch (error) {
    controller.abort(error)
    await peers.close().catch(() => undefined)
    throw error
  }
}

/** Subscribe before checking so materialization/finality changes cannot be missed. */
export async function waitForFinalAcceptance(node: ChronologNode, txId: Uint8Array, signal?: AbortSignal): Promise<void> {
  signal?.throwIfAborted()
  const waiting = new AbortController()
  const abort = (): void => waiting.abort(signal?.reason)
  signal?.addEventListener('abort', abort, { once: true })
  if (signal?.aborted) waiting.abort()
  const revisions = node.revisions(0n, waiting.signal)
  const accepted = (): boolean => {
    if (!node.isFinal(txId)) return false
    const outcome = node.outcome(txId)
    if (outcome === null) throw new Error('AGENT_FINAL_OUTCOME_MISSING')
    if (outcome.outcome !== 'accepted') throw new Error(`AGENT_PUBLICATION_REJECTED: ${outcome.rejectionCode ?? 'unknown'}`)
    return true
  }
  try {
    if (accepted()) return
    for await (const _revision of revisions) if (accepted()) return
    signal?.throwIfAborted()
    throw new Error('AGENT_FINALITY_WAIT_INTERRUPTED')
  } finally {
    waiting.abort()
    signal?.removeEventListener('abort', abort)
  }
}

export async function readFinalityContinuity(path: string): Promise<OrderedRecordHead> {
  const value = JSON.parse(await readFile(resolve(path), 'utf8')) as unknown
  if (typeof value !== 'object' || value === null || !('historyId' in value) || !('position' in value) || !('root' in value) ||
      typeof value.historyId !== 'string' || !/^h_[0-9a-f]{32}$/u.test(value.historyId) ||
      typeof value.position !== 'number' || !Number.isSafeInteger(value.position) || value.position < 0 ||
      typeof value.root !== 'string' || !/^[0-9a-f]{64}$/u.test(value.root)) throw new Error('AUTHORITY_CONTINUITY_FILE_INVALID')
  return { historyId: value.historyId, position: value.position, root: value.root }
}

async function loadApplicationModule(path: string): Promise<AgentApplicationModule> {
  const loaded: unknown = await import(pathToFileURL(resolve(path)).href)
  if (typeof loaded !== 'object' || loaded === null || !('createAgent' in loaded) || typeof loaded.createAgent !== 'function') {
    throw new Error('AGENT_MODULE_CREATE_AGENT_REQUIRED')
  }
  return loaded as AgentApplicationModule
}

