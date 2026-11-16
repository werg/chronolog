import { readFile } from 'node:fs/promises'
import { resolve } from 'node:path'
import { pathToFileURL } from 'node:url'

import {
  DurableEffectWorker, DurableTimerScheduler, EphemeralChannel, NativeAuthority, ResidentAgentService, openAuthenticatedPeerLink,
} from '@chronolog/agent-service'
import type {
  AgentApplicationContext, AgentApplicationModule, FinalEventPublisher, ResidentTask,
} from '@chronolog/agent-service'
import { isCapabilityActive } from '@chronolog/capabilities'
import type { CapabilitySnapshot } from '@chronolog/capabilities'
import type {
  ChronologNode, DurableOperationStore, HistoryConfiguration, OrderedRecordHead,
} from '@chronolog/node-core'
import { bytesToHex, equalBytes } from '@chronolog/protocol'
import type { Ed25519KeyPair } from '@chronolog/protocol'
import type { ChronologTransport, FeedLink } from '@chronolog/records'

export interface DaemonAgentRuntimeOptions {
  readonly node: ChronologNode
  readonly transport: ChronologTransport
  readonly store: DurableOperationStore
  readonly identity: Ed25519KeyPair
  readonly history: HistoryConfiguration
  readonly activeMembership?: () => CapabilitySnapshot
  readonly authorityQuotaBytes?: number
  readonly continuity?: OrderedRecordHead
  readonly modulePath?: string
  /** Dependency injection for native integration tests and embedded deployments. */
  readonly application?: AgentApplicationModule
  readonly peerLinks?: { readonly local: FeedLink; attach(link: FeedLink): () => void }
}

export async function createDaemonAgentRuntime(options: DaemonAgentRuntimeOptions) {
  const sourceId = `${bytesToHex(options.history.groupId)}/${options.history.kind === 'coordinated'
    ? options.history.historyId : bytesToHex(options.history.genesisDigest)}`
  const authority = options.history.kind === 'coordinated' && equalBytes(options.history.authorityPublicKey, options.identity.publicKeyBytes)
    ? await NativeAuthority.open({ configuration: options.history, identity: options.identity, store: options.store,
      ...(options.authorityQuotaBytes === undefined ? {} : { quotaBytes: options.authorityQuotaBytes }),
      ...(options.continuity === undefined ? {} : { continuity: options.continuity }) })
    : null
  if (authority === null && options.continuity !== undefined) throw new Error('AUTHORITY_CONTINUITY_WITHOUT_LOCAL_AUTHORITY')
  const controller = new AbortController()
  const channels = new Set<EphemeralChannel>()
  const peerClosers = new Set<() => Promise<void>>()
  const publisher: FinalEventPublisher = {
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
    node: options.node, store: options.store, authority, publisher, sourceId,
    createSignals: async (input) => {
      if (options.activeMembership === undefined) throw new Error('SIGNAL_GOVERNANCE_REQUIRED')
      const channel = await EphemeralChannel.open({ groupId: options.history.groupId, identity: options.identity,
        grantId: input.grantId, send: input.send,
        authorize: ({ authorId, grantId, topic }) => {
          const snapshot = options.activeMembership!()
          if (!equalBytes(snapshot.groupId, options.history.groupId)) return false
          const capability = snapshot.capabilities.get(bytesToHex(grantId))
          const topics = capability?.grant.program?.signals
          return capability !== undefined && capability.grant.role === 'writer' &&
            isCapabilityActive(capability, snapshot.revision) && equalBytes(capability.grant.signingPublicKey, authorId) &&
            topics !== undefined && (topics.includes('*') || topics.includes(topic))
        },
      })
      channels.add(channel)
      return channel
    },
    connectPeer: async (input) => {
      if (options.activeMembership === undefined || options.peerLinks === undefined) throw new Error('PEER_GOVERNANCE_TRANSPORT_REQUIRED')
      const current = options.activeMembership()
      const reader = input.grantId ?? [...current.capabilities.values()].find((capability) => capability.grant.role === 'reader' &&
        isCapabilityActive(capability, current.revision) && equalBytes(capability.grant.signingPublicKey, options.identity.publicKeyBytes))?.id
      if (reader === undefined) throw new Error('PEER_LOCAL_READER_GRANT_REQUIRED')
      const session = await openAuthenticatedPeerLink({ connection: input.connection, local: options.peerLinks.local,
        identity: options.identity, groupId: options.history.groupId, grantId: reader,
        authorizePeer: ({ authorId, grantId }) => {
          const snapshot = options.activeMembership!(), capability = snapshot.capabilities.get(bytesToHex(grantId))
          return equalBytes(snapshot.groupId, options.history.groupId) && capability !== undefined &&
            capability.grant.role === 'reader' && isCapabilityActive(capability, snapshot.revision) &&
            equalBytes(capability.grant.signingPublicKey, authorId)
        },
        ...(input.signals === undefined ? {} : { receiveSignal: async (frame: Uint8Array) => { await input.signals!.receive(frame) } }),
      })
      const detach = options.peerLinks.attach(session.link)
      const close = async (): Promise<void> => { detach(); await session.close(); peerClosers.delete(close) }
      peerClosers.add(close)
      void session.completion.finally(() => { detach(); peerClosers.delete(close) }).catch(() => undefined)
      return { completion: session.completion, sendSignal: (bytes) => session.sendSignal(bytes), close }
    },
  }
  if (options.application !== undefined && options.modulePath !== undefined) throw new Error('AGENT_MODULE_DUPLICATE')
  const application = options.application ?? (options.modulePath === undefined ? undefined : await loadApplicationModule(options.modulePath))
  const definition = application === undefined ? {} : await application.createAgent(context)
  const tasks: ResidentTask[] = authority === null ? [] : [{ id: 'authority', run: (signal) => authority.serve(options.transport, signal) }]
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
    authority, effects, timers, context,
    get taskIds() { return tasks.map((task) => task.id) },
    get status() { return service?.status ?? { running: false, failedTask: null } },
    run(): Promise<void> {
      if (running !== null) throw new Error('AGENT_SERVICE_ALREADY_RUNNING')
      if (controller.signal.aborted) throw new Error('AGENT_SERVICE_STOPPED')
      running = service?.run(controller.signal) ?? Promise.resolve()
      return running
    },
    async close(): Promise<void> {
      controller.abort()
      for (const channel of channels) channel.close()
      await Promise.all([...peerClosers].map((close) => close()))
      if (running !== null) await running.catch(() => undefined)
    },
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

export async function readAuthorityContinuity(path: string): Promise<OrderedRecordHead> {
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

