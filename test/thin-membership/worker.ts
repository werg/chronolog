import { decodeSignedGenesis, isCapabilityActive } from '@chronolog/capabilities'
import { ChronologClient } from '@chronolog/client'
import { SignedInclusionFinalityProvider, type EnrollmentIdentity } from '@chronolog/node-core/browser'
import { LedgerRecordError } from '@chronolog/node-core/ledger'
import { decodeMembershipLedgerResponse } from '@chronolog/node-core/membership'
import { base64UrlToBytes, bytesToBase64Url, decodeExecutionManifest, emit, equalBytes, program } from '@chronolog/protocol'
import { feedIdFromPublicKey } from '@chronolog/records'
import { openBrowserPeer, prepareBrowserIdentity, type BrowserPeer, type WorkerEndpoint } from '@chronolog/runtime-browser'
import { frameRtcPeerChannels, type PeerDataChannelConnection, type WebRtcChannels } from '@chronolog/transport-webrtc'

import { attachMembershipPeer } from './peer.js'
import type { ThinMembershipBootstrap } from '../../tools/thin-membership-native.js'

type Request = {
  readonly id: number
  readonly method: 'prepare' | 'open' | 'request' | 'approval' | 'history' | 'channel' | 'disconnect' | 'sync' |
    'publish' | 'operation' | 'events' | 'status' | 'progress' | 'close'
  readonly name?: string
  readonly bootstrap?: ThinMembershipBootstrap
  readonly requestId?: string
  readonly signedApproval?: string
  readonly pages?: readonly string[]
  readonly operationId?: string
  readonly text?: string
  readonly channels?: WebRtcChannels
  readonly connectionId?: number
}

const endpoint = globalThis as unknown as WorkerEndpoint
let peer: BrowserPeer | undefined, client: ChronologClient | undefined, identity: EnrollmentIdentity | undefined
let bootstrap: ThinMembershipBootstrap | undefined
let connection: Awaited<ReturnType<typeof attachMembershipPeer>> | undefined
let opening: PeerDataChannelConnection | undefined, connectionGeneration = 0
let connectionError: string | undefined
let requestId: string | undefined

// Qualification timings observe the public provider/store boundaries. They do
// not issue extra reads, drain queues, or change the evidence being verified.
const workNames = ['transportCatchUp', 'evidenceHistory', 'nodeIdle', 'finalityIngest',
  'finalitySnapshot', 'finalityStoreRead', 'finalityStoreWrite', 'enrollmentStatus'] as const
type WorkName = typeof workNames[number]
const work = Object.fromEntries(workNames.map(name => [name, {
  calls: 0, completed: 0, failed: 0, inputBytes: 0, outputBytes: 0, totalMs: 0, maximumMs: 0,
  active: new Map<number, number>(),
}])) as Record<WorkName, { calls: number; completed: number; failed: number; inputBytes: number; outputBytes: number
  totalMs: number; maximumMs: number; active: Map<number, number> }>
const evidenceInputs = new Set<string>()
let repeatedEvidenceInputs = 0, scannedEvidenceEntries = 0
let finality: { includedThrough: number; closedReceiptThrough: number; closedThroughMs: string } | undefined
let sync: { command: number; startedAtMs: number; phase: string; phaseStartedAtMs: number; finishedAtMs?: number
  phases: Array<{ name: string; elapsedMs: number }>; evidenceBefore: { unique: number; repeated: number } } | undefined

function beginWork(name: WorkName, bytes = 0): (failed?: boolean, outputBytes?: number) => void {
  const metric = work[name], id = ++metric.calls, startedAtMs = performance.now()
  metric.inputBytes += bytes; metric.active.set(id, startedAtMs)
  return (failed = false, outputBytes = 0) => {
    const elapsedMs = performance.now() - startedAtMs
    metric.active.delete(id); metric.completed++; metric.failed += Number(failed)
    metric.outputBytes += outputBytes; metric.totalMs += elapsedMs; metric.maximumMs = Math.max(metric.maximumMs, elapsedMs)
  }
}

async function measured<T>(name: WorkName, run: () => Promise<T>, bytes = 0): Promise<T> {
  const finish = beginWork(name, bytes)
  try { const result = await run(); finish(false, result instanceof Uint8Array ? result.length : 0); return result }
  catch (error) { finish(true); throw error }
}

function syncPhase(name: string): void {
  if (sync === undefined) return
  const now = performance.now()
  sync.phases.push({ name: sync.phase, elapsedMs: now - sync.phaseStartedAtMs })
  sync.phase = name; sync.phaseStartedAtMs = now
  if (name === 'completed' || name === 'failed') sync.finishedAtMs = now
}

function diagnostics() {
  const now = performance.now()
  return {
    sync: sync === undefined ? null : { command: sync.command, phase: sync.phase,
      elapsedMs: (sync.finishedAtMs ?? now) - sync.startedAtMs,
      phaseAgeMs: (sync.finishedAtMs ?? now) - sync.phaseStartedAtMs, phases: sync.phases,
      evidenceBefore: sync.evidenceBefore },
    evidence: { uniqueInputs: evidenceInputs.size, repeatedInputs: repeatedEvidenceInputs, scannedEntries: scannedEvidenceEntries },
    finality,
    // Durations include waiting for the observed call and may overlap between
    // the background consumer and the explicit idle barrier.
    work: Object.fromEntries(workNames.map(name => {
      const { active, ...metric } = work[name]
      return [name, { ...metric, pending: active.size,
        oldestPendingMs: active.size === 0 ? 0 : now - Math.min(...active.values()) }]
    })),
  }
}

async function disconnect(): Promise<void> {
  connectionGeneration++
  const pending = opening; opening = undefined
  const previous = connection; connection = undefined
  await Promise.all([pending?.close(), previous?.close()])
}

async function status(syncing = false) {
  if (peer === undefined || identity === undefined || client === undefined) throw new Error('THIN_BROWSER_NOT_OPEN')
  let applicationBlockedOnPayload = false
  if (syncing) syncPhase('node.waitForIdle')
  try { await measured('nodeIdle', () => peer!.node.waitForIdle()) }
  catch (error) {
    if (!(error instanceof Error && error.cause instanceof LedgerRecordError && error.cause.code === 'LEDGER_PAYLOAD_UNAVAILABLE')) throw error
    applicationBlockedOnPayload = true
  }
  const membership = peer.governed!.activeSnapshot
  if (syncing) syncPhase('enrollment.getStatus')
  const enrollment = requestId === undefined ? null : await measured('enrollmentStatus', () => client!.enrollment.getStatus(requestId!))
  return { identity: bytesToBase64Url(identity.signing.publicKeyBytes), connected: connection !== undefined,
    connectionError, rtc: connection?.stats() ?? null, applicationBlockedOnPayload, membershipRevision: String(membership.revision), finalThrough: peer.node.finalThrough,
    availableEpochs: peer.governed!.governance.cipherRing.epochs().map(String),
    knownEpochs: peer.governed!.governance.knownEpochs.map(String),
    grants: [...membership.capabilities.values()].filter(capability =>
      equalBytes(capability.grant.signingPublicKey, identity!.signing.publicKeyBytes)).map(capability => ({
        id: bytesToBase64Url(capability.id), role: capability.grant.role, active: isCapabilityActive(capability, membership.revision),
      })),
    enrollment, diagnostics: diagnostics() }
}

endpoint.addEventListener('message', event => {
  const request = event.data as Request
  const run = async (): Promise<unknown> => {
    switch (request.method) {
      case 'prepare': {
        const device = await prepareBrowserIdentity(request.name!, true)
        return { signingPublicKey: bytesToBase64Url(device.signing.publicKeyBytes), readerPublicKey: bytesToBase64Url(device.reader.publicKeyBytes),
          transportAuthor: feedIdFromPublicKey(device.signing.publicKeyBytes) }
      }
      case 'open': {
        if (peer !== undefined) throw new Error('THIN_BROWSER_ALREADY_OPEN')
        bootstrap = request.bootstrap!
        const genesis = decodeSignedGenesis(base64UrlToBytes(bootstrap.genesis))
        peer = await openBrowserPeer({ name: request.name!, engineUrl: new URL('./engine/', globalThis.location.href), configure(context) {
          identity = context.identity
          const evidenceHistory = context.transport.evidenceHistory.bind(context.transport)
          context.transport.evidenceHistory = () => measured('evidenceHistory', async () => {
            const history = await evidenceHistory()
            scannedEvidenceEntries += history.length
            return history
          })
          return { materializer: { executionManifest: decodeExecutionManifest(base64UrlToBytes(bootstrap!.executionManifest)),
            rootAdministrator: genesis.manifest.schemaAdminPublicKey },
            governed: { genesis, groupRoute: base64UrlToBytes(bootstrap!.groupRoute), finalityProviders: {
              'signed-inclusion-v2': async (configuration, store) => {
                const provider = await SignedInclusionFinalityProvider.open(configuration, {
                  get: key => measured('finalityStoreRead', () => store.get(key)),
                  put: (key, bytes) => measured('finalityStoreWrite', () => store.put(key, bytes), bytes.length),
                })
                return { configuration: provider.configuration, evidenceBytes: () => provider.evidenceBytes(),
                  async ingestEvidence(bytes) {
                    const key = bytesToBase64Url(bytes)
                    if (evidenceInputs.has(key)) repeatedEvidenceInputs++; else evidenceInputs.add(key)
                    return measured('finalityIngest', () => provider.ingestEvidence(bytes), bytes.length)
                  },
                  snapshot() {
                    const finish = beginWork('finalitySnapshot')
                    try {
                      const snapshot = provider.snapshot()
                      finality = { includedThrough: snapshot.includedThrough, closedReceiptThrough: snapshot.closedReceiptThrough,
                        closedThroughMs: String(snapshot.closedThroughMs) }
                      finish(); return snapshot
                    } catch (error) { finish(true); throw error }
                  },
                }
              },
            } }, close: disconnect }
        } })
        client = new ChronologClient({ groupId: bytesToBase64Url(genesis.manifest.groupId), transport: peer.rpc, unaryRetryAttempts: 1 })
        return status()
      }
      case 'request': {
        requestId = request.requestId!
        return client!.enrollment.createRequest({ requestId, roles: ['reader', 'writer'],
          writerProgram: { sql: true, topics: ['qualification'], signals: [] } })
      }
      case 'approval': {
        requestId = request.requestId!
        await client!.enrollment.getStatus(requestId, { signedApproval: request.signedApproval! })
        return status()
      }
      case 'history': {
        for (const bytes of request.pages!) {
          const page = decodeMembershipLedgerResponse(base64UrlToBytes(bytes), 'read')
          await peer!.governed!.ingestMembership(page)
        }
        return status()
      }
      case 'channel': {
        if (connection !== undefined || opening !== undefined) { request.channels!.reliable.close(); request.channels!.live.close(); throw new Error('THIN_BROWSER_ALREADY_CONNECTED') }
        connectionError = undefined
        const generation = ++connectionGeneration, framed = frameRtcPeerChannels(request.channels!)
        opening = framed
        try {
          const attached = await attachMembershipPeer({ connection: framed,
            nativeIdentity: bootstrap!.nativeIdentity, peer: peer! })
          if (generation !== connectionGeneration) { await attached.close(); throw new Error('THIN_BROWSER_ATTACHMENT_SUPERSEDED') }
          connection = attached
        } finally { if (opening === framed) opening = undefined }
        const active = connection
        void active.completion.catch((error: unknown) => { if (connection === active) connectionError = String(error) })
          .finally(() => {
            if (connection === active) {
              connection = undefined
              endpoint.postMessage({ kind: 'peer-ended', connectionId: request.connectionId, error: connectionError })
            }
          })
        // Attachment owns only RTC/framing and the peer identity proof. The
        // caller's explicit sync owns retained history and SQL materialization.
        return { connected: true, rtc: active.stats() }
      }
      case 'disconnect': await disconnect(); return null
      case 'sync': {
        if (connectionError !== undefined) throw new Error(connectionError)
        const now = performance.now()
        sync = { command: request.id, startedAtMs: now, phase: 'transport.catchUp', phaseStartedAtMs: now,
          phases: [], evidenceBefore: { unique: evidenceInputs.size, repeated: repeatedEvidenceInputs } }
        try {
          await measured('transportCatchUp', () => peer!.transport.catchUp())
          const current = await status(true)
          if (connectionError !== undefined) throw new Error(connectionError)
          syncPhase('completed')
          return { ...current, diagnostics: diagnostics() }
        } catch (error) { syncPhase('failed'); throw error }
      }
      case 'publish': {
        const handle = await client!.submit(program(emit('qualification', { text: request.text! })), { operationId: request.operationId! })
        try { return { operationId: request.operationId, proposalId: handle.proposalId } } finally { handle.dispose() }
      }
      case 'operation': return client!.operations.get(request.operationId!)
      case 'events': return client!.events.read({ topics: ['qualification'] })
      case 'status': return status()
      // Diagnostics observe current state without entering the SQL replay mutex.
      case 'progress': return { opened: peer !== undefined, connected: connection !== undefined, connectionError,
        rtc: connection?.stats() ?? null, node: await peer?.node.status(), finalThrough: peer?.node.finalThrough,
        diagnostics: diagnostics() }
      case 'close': await client?.close(); await peer?.close(); client = undefined; peer = undefined; return null
    }
  }
  void run().then(value => endpoint.postMessage({ id: request.id, value }),
    (error: unknown) => endpoint.postMessage({ id: request.id, error: error instanceof Error ? error.stack : String(error) }))
})
