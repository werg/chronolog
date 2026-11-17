import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import type { SignedGenesis } from '@chronolog/capabilities'
import { NodeStateDatabase, SqliteControlStorePersistence, ControlStore } from '../packages/control-store/src/index.js'
import { DeterministicMaterializer, createDoltLiteExecutionManifest, createDoltLiteMaterializationRuntime } from '@chronolog/materializer-doltlite'
import { createGovernedNode, type GovernedNode } from '@chronolog/node-core'
import { generateEd25519KeyPair, executionManifestArtifacts, sqlStatement, decodeEnvelope, equalBytes } from '@chronolog/protocol'
import { MemoryTransportNetwork } from '@chronolog/transport-ssb'
import { afterEach, describe, expect, it } from 'vitest'

import { createEnrollmentService } from '../packages/node-core/src/enrollment-service.js'
import { loadOrCreateGovernanceBootstrap } from '../apps/chronologd/src/governance-config.js'
import { SqliteOperationStore } from '../apps/chronologd/src/operation-store.js'

const cleanup: Array<() => Promise<void>> = []
afterEach(async () => { for (const close of cleanup.splice(0).reverse()) await close() })

describe('live native governed peer', () => {
  it('enrolls a new writer with full history, closes revoked grants, and keeps earlier final SQL stable', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'chronolog-governed-peer-'))
    cleanup.push(() => rm(directory, { recursive: true, force: true }))
    const network = new MemoryTransportNetwork()
    const manifest = createDoltLiteExecutionManifest()
    const { executionManifestDigest } = await executionManifestArtifacts(manifest)
    const groupId = new Uint8Array(32).fill(81), groupRoute = new Uint8Array(32).fill(82)
    let now = 1_000
    const open = async (name: string, adopt?: SignedGenesis) => {
      const transport = network.createNode(name)
      const identity = await generateEd25519KeyPair()
      const path = join(directory, name)
      const bootstrap = await loadOrCreateGovernanceBootstrap({
        dataDirectory: path, groupId, schemaId: executionManifestDigest, identity, transportAuthor: transport.identity,
        clockPolicy: { cutoffLagMs: 10n, maxFutureSkewMs: 30_000n, heartbeatIntervalMs: 30_000n },
        ...(adopt === undefined ? {} : { bootstrap: { adopt } }),
      })
      const state = new NodeStateDatabase(join(path, 'state.sqlite'))
      const store = new SqliteOperationStore(state.database)
      const materializer = await DeterministicMaterializer.open({ path: join(path, 'application.db'), executionManifest: manifest,
        rootAdministrator: bootstrap.genesis.manifest.schemaAdminPublicKey })
      const runtime = await createGovernedNode({
        genesis: bootstrap.genesis, groupRoute, identity, transport,
        recipient: { id: bootstrap.recipientId, privateKey: bootstrap.recipientPrivateKey },
        operationStore: store, materialization: createDoltLiteMaterializationRuntime(materializer),
        controlStore: new ControlStore(new SqliteControlStorePersistence(state)),
        clock: { now: () => now },
      })
      cleanup.push(async () => { await runtime.close(); state.close() })
      const enrollment = createEnrollmentService({
        descriptor: runtime.descriptor, store, identity, readerPublicKey: bootstrap.recipientPublicKey,
        transportAuthor: transport.identity, governance: runtime.governance,
        activeMembership: () => runtime.activeSnapshot,
        ...(runtime.enrollmentIssuer === undefined ? {} : { issuer: runtime.enrollmentIssuer }),
        connected: async () => (await transport.status()).peers.length > 0 || runtime.governance.ownsCapabilityFeed,
        executionManifestDigest, isFinalTargetApplied: (target) => runtime.node.isFinalTargetApplied(target.frontier),
      })
      return { runtime, transport, identity, bootstrap, enrollment }
    }
    const root = await open('root')
    await root.runtime.start()
    const validatorGrant = [...root.runtime.activeSnapshot.capabilities.values()].find((entry) => entry.grant.role === 'validator')!
    const initialRecords = (await root.transport.history()).length
    await expect(root.runtime.governance.publishCapabilityChange({ revocations: [validatorGrant.id] }, root.identity.privateKey))
      .rejects.toThrow('GOVERNANCE_FIXED_VALIDATORS')
    await expect(root.runtime.governance.publishCapabilityChange({ successorRootPublicKey: new Uint8Array(32).fill(90) }, root.identity.privateKey))
      .rejects.toThrow('GOVERNANCE_FIXED_ROOT')
    await expect(root.runtime.governance.publishCapabilityChange({ validationPolicies: [{ version: 2n, minimumValidators: 0n }] }, root.identity.privateKey))
      .rejects.toThrow('GOVERNANCE_FIXED_VALIDATION_POLICY')
    expect((await root.transport.history()).length).toBe(initialRecords)
    const original = await root.runtime.node.publish({ operationId: 'schema', program: { version: 3, steps: [
      sqlStatement('CREATE TABLE messages (id INTEGER PRIMARY KEY, body TEXT NOT NULL)'),
      sqlStatement("INSERT INTO messages (id, body) VALUES (0, 'historical')"),
    ] } })
    await settle(root.runtime, original.txId)
    expect(root.runtime.node.isFinal(original.txId)).toBe(false)
    now = 2_000
    await root.runtime.node.publishHeartbeat()
    await eventually(async () => { await root.runtime.node.waitForIdle(); return root.runtime.node.isFinal(original.txId) })
    const target = await root.runtime.node.finalTarget()

    const newcomer = await open('newcomer', root.bootstrap.genesis)
    network.connect(root.transport, newcomer.transport)
    await newcomer.runtime.start()
    expect(await newcomer.runtime.node.isWritable()).toBe(false)
    const request = await newcomer.enrollment.createRequest({ requestId: 'join-device', roles: ['reader', 'writer'], writerProgram: { sql: true, topics: [], signals: [] } })
    expect(await newcomer.enrollment.createRequest({ requestId: 'join-device', roles: ['reader', 'writer'], writerProgram: { sql: true, topics: [], signals: [] } })).toEqual(request)
    const decision = { requestId: 'approve-device', signedRequest: request.signedRequest,
      roles: ['reader', 'writer'] as const, grantFullHistory: true, writerProgram: { sql: true, topics: [], signals: [] } }
    const approval = await root.enrollment.approveRequest(decision)
    expect(await root.enrollment.approveRequest(decision)).toEqual(approval)
    await eventually(async () => {
      await newcomer.runtime.node.refreshMembership()
      const progress = await newcomer.enrollment.getStatus({ requestId: 'join-device', signedApproval: approval.signedApproval })
      return progress.state === 'ready'
    })
    expect(await newcomer.runtime.node.isFinalTargetApplied(target)).toBe(true)
    expect(newcomer.runtime.node.localSql('SELECT body FROM messages', [], { view: 'final' }).rows)
      .toEqual([[{ kind: 'text', value: 'historical' }]])
    expect(newcomer.runtime.node.candidateCore(original.txId)?.writerCapability).toBeDefined()

    now = 3_000
    const authored = await newcomer.runtime.node.publish({ operationId: 'insert-own-row', program: { version: 3,
      steps: [sqlStatement("INSERT INTO messages (id, body) VALUES (1, 'new device')")] } })
    await settle(root.runtime, authored.txId)
    await settle(newcomer.runtime, authored.txId)
    const grant = newcomer.runtime.node.candidateCore(authored.txId)!.writerCapability!
    const oldRevision = newcomer.runtime.node.membershipRevision
    await root.runtime.governance.publishCapabilityChange({ revocations: [grant] }, root.identity.privateKey,
      { operationId: 'revoke-device' })
    await eventually(async () => {
      await root.runtime.node.refreshMembership(); await newcomer.runtime.node.refreshMembership()
      return root.runtime.activeSnapshot.revision === 2n && newcomer.runtime.activeSnapshot.revision === 2n
    })
    await eventually(async () => { await root.runtime.node.waitForIdle(); return root.runtime.node.isFinal(authored.txId) })
    expect(await newcomer.runtime.node.isWritable()).toBe(false)
    expect(await newcomer.runtime.node.publish({ operationId: 'insert-own-row', program: { version: 3,
      steps: [sqlStatement("INSERT INTO messages (id, body) VALUES (1, 'new device')")] } })).toEqual(authored)
    await expect(newcomer.runtime.node.publish({ operationId: 'after-revoke', program: { version: 3,
      steps: [sqlStatement("INSERT INTO messages (id, body) VALUES (2, 'forbidden')")] } })).rejects.toThrow('WRITER_UNAUTHORIZED')
    expect(root.runtime.peerGovernance!.closedAdmissionRevisions().some(item => equalBytes(item.membershipRevision, oldRevision))).toBe(true)
    expect(root.runtime.node.localSql('SELECT body FROM messages ORDER BY id', [], { view: 'final' }).rows)
      .toEqual([[{ kind: 'text', value: 'historical' }], [{ kind: 'text', value: 'new device' }]])
    expect((await root.transport.history()).filter((record) => decodeEnvelope(record.payload).messageType === 'proof-bundle'))
      .toHaveLength(2)
  })
})

async function settle(runtime: GovernedNode, txId: Uint8Array): Promise<void> {
  await eventually(async () => {
    await runtime.node.waitForIdle()
    return runtime.node.outcome(txId) !== null
  })
  expect(runtime.node.outcome(txId)?.outcome).toBe('accepted')
}

async function eventually(check: () => Promise<boolean>): Promise<void> {
  const deadline = Date.now() + 5_000
  while (!await check()) {
    if (Date.now() > deadline) throw new Error('governed peer did not converge')
    await new Promise((resolve) => setTimeout(resolve, 5))
  }
}
