import { decodeSignedGenesis, isCapabilityActive } from '@chronolog/capabilities'
import { ChronologClient } from '@chronolog/client'
import type { EnrollmentIdentity } from '@chronolog/node-core/browser'
import { encodeOrderingEvidence } from '@chronolog/node-core/history'
import { LedgerRecordError } from '@chronolog/node-core/ledger'
import { decodeMembershipLedgerResponse } from '@chronolog/node-core/membership'
import { base64UrlToBytes, bytesToBase64Url, decodeExecutionManifest, emit, equalBytes, program } from '@chronolog/protocol'
import { feedIdFromPublicKey } from '@chronolog/records'
import { openBrowserPeer, prepareBrowserIdentity, type BrowserPeer, type WorkerEndpoint } from '@chronolog/runtime-browser'
import { frameRtcDataChannel, type RtcDataChannel } from '@chronolog/transport-webrtc'

import { attachMembershipPeer } from './peer.js'
import type { ThinMembershipBootstrap } from '../../tools/thin-membership-native.js'

type Request = {
  readonly id: number
  readonly method: 'prepare' | 'open' | 'request' | 'approval' | 'history' | 'channel' | 'disconnect' | 'sync' |
    'publish' | 'operation' | 'events' | 'status' | 'close'
  readonly name?: string
  readonly bootstrap?: ThinMembershipBootstrap
  readonly requestId?: string
  readonly signedApproval?: string
  readonly pages?: readonly string[]
  readonly operationId?: string
  readonly text?: string
  readonly channel?: RtcDataChannel
}

const endpoint = globalThis as unknown as WorkerEndpoint
let peer: BrowserPeer | undefined, client: ChronologClient | undefined, identity: EnrollmentIdentity | undefined
let bootstrap: ThinMembershipBootstrap | undefined
let connection: Awaited<ReturnType<typeof attachMembershipPeer>> | undefined
let connectionError: string | undefined
let requestId: string | undefined

async function disconnect(): Promise<void> {
  const previous = connection; connection = undefined
  await previous?.close()
}

async function status() {
  if (peer === undefined || identity === undefined || client === undefined) throw new Error('THIN_BROWSER_NOT_OPEN')
  let applicationBlockedOnPayload = false
  try { await peer.node.waitForIdle() }
  catch (error) {
    if (!(error instanceof Error && error.cause instanceof LedgerRecordError && error.cause.code === 'LEDGER_PAYLOAD_UNAVAILABLE')) throw error
    applicationBlockedOnPayload = true
  }
  const membership = peer.governed!.activeSnapshot
  return { identity: bytesToBase64Url(identity.signing.publicKeyBytes), connected: connection !== undefined,
    connectionError, rtc: connection?.stats() ?? null, applicationBlockedOnPayload, membershipRevision: String(membership.revision), finalThrough: peer.node.finalThrough,
    availableEpochs: peer.governed!.governance.cipherRing.epochs().map(String),
    knownEpochs: peer.governed!.governance.knownEpochs.map(String),
    grants: [...membership.capabilities.values()].filter(capability =>
      equalBytes(capability.grant.signingPublicKey, identity!.signing.publicKeyBytes)).map(capability => ({
        id: bytesToBase64Url(capability.id), role: capability.grant.role, active: isCapabilityActive(capability, membership.revision),
      })),
    enrollment: requestId === undefined ? null : await client.enrollment.getStatus(requestId) }
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
          return { materializer: { executionManifest: decodeExecutionManifest(base64UrlToBytes(bootstrap!.executionManifest)),
            rootAdministrator: genesis.manifest.schemaAdminPublicKey },
            governed: { genesis, groupRoute: base64UrlToBytes(bootstrap!.groupRoute) }, close: disconnect }
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
          for (const entry of page.entries) await peer!.transport.putEvidence(encodeOrderingEvidence({ kind: 'ordered-entry', entry }))
          await peer!.transport.putEvidence(encodeOrderingEvidence({ kind: 'prefix-certificate', certificate: page.certificate }))
        }
        return status()
      }
      case 'channel': {
        if (connection !== undefined) { request.channel!.close(); throw new Error('THIN_BROWSER_ALREADY_CONNECTED') }
        connectionError = undefined
        connection = await attachMembershipPeer({ connection: frameRtcDataChannel(request.channel!),
          nativeIdentity: bootstrap!.nativeIdentity, identity: identity!, transport: peer!.transport,
          activeMembership: () => peer!.governed!.activeSnapshot })
        const active = connection
        void active.completion.catch((error: unknown) => { if (connection === active) connectionError = String(error) })
          .finally(() => { if (connection === active) connection = undefined })
        await peer!.transport.catchUp()
        return status()
      }
      case 'disconnect': await disconnect(); return status()
      case 'sync': await peer!.transport.catchUp(); return status()
      case 'publish': {
        const handle = await client!.submit(program(emit('qualification', { text: request.text! })), { operationId: request.operationId! })
        try { return { operationId: request.operationId, proposalId: handle.proposalId } } finally { handle.dispose() }
      }
      case 'operation': return client!.operations.get(request.operationId!)
      case 'events': return client!.events.read({ topics: ['qualification'] })
      case 'status': return status()
      case 'close': await client?.close(); await peer?.close(); client = undefined; peer = undefined; return null
    }
  }
  void run().then(value => endpoint.postMessage({ id: request.id, value }),
    (error: unknown) => endpoint.postMessage({ id: request.id, error: error instanceof Error ? error.stack : String(error) }))
})
