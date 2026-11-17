import assert from 'node:assert/strict'
import { mkdir, readFile, stat } from 'node:fs/promises'
import { join } from 'node:path'

import { NativeAgentStore } from '@chronolog/agent-service'
import { decodeSignedGenesis, encodeGenesisManifest, verifySignedGenesis } from '@chronolog/capabilities'
import { ControlStore, NodeStateDatabase, SqliteControlStorePersistence } from '@chronolog/control-store'
import { createDoltLiteExecutionManifest, createDoltLiteMaterializationRuntime, DeterministicMaterializer } from '@chronolog/materializer-doltlite'
import {
  createGovernedNode, decodeFinalityClosureRecord, decodeLedgerRecord, decodeOrderingEvidence,
  isFinalityClosureRecord, loadOrCreateEnrollmentIdentity,
  evaluateFinalitySnapshot, orderedGenesisRoot, ReferenceRecordLog, verifyPrefixCertificate,
  type CoordinatedHistoryConfiguration, type DurableOperationStore, type OrderedRecordHead,
} from '@chronolog/node-core'
import {
  assertCanonicalCbor, bytesToBase64Url, bytesToHex, decodeEnvelope, DOMAINS, emit, encodeCanonicalCbor, executionManifestArtifacts, hashDomain, program, sqlStatement,
} from '@chronolog/protocol'
import { DurableFeedStore, feedIdFromPublicKey, PortableFeedTransport, webFeedCrypto, webFeedSigner } from '@chronolog/records'

import { createDaemonAgentRuntime } from '../../apps/chronologd/src/agent-runtime.js'
import { loadOrCreateGovernanceBootstrap } from '../../apps/chronologd/src/governance-config.js'

export const AUTHORITY_CRASH_POINTS = [
  'before_payload_commit', 'after_payload_commit', 'before_record_commit',
  'after_record_commit', 'before_closure_commit', 'after_closure_commit',
  'before_certificate_commit', 'after_certificate_commit', 'before_acknowledgement',
] as const
export type AuthorityCrashPoint = typeof AUTHORITY_CRASH_POINTS[number]
export type RecoveryOperation = 'accepted' | 'rejected'

export function recoveryProgram(kind: RecoveryOperation) {
  return program(
    sqlStatement('UPDATE recovery_probe SET value = ? WHERE id = 1', [kind === 'accepted' ? 20 : 99]),
    emit('recovery.changed', { value: kind === 'accepted' ? 20 : 99 }),
    ...(kind === 'accepted' ? [] : [sqlStatement("SELECT chronolog_assert(0, 'recovery_probe')")]),
  )
}

/** Actual persistent SQL/core/authority composition; no network adapter or provider is simulated. */
export async function openAuthorityRecoveryFixture(directory: string, options: {
  readonly create?: boolean
  readonly continuity?: OrderedRecordHead
  readonly fault?: (point: AuthorityCrashPoint) => void
} = {}) {
  if (options.create === true) await mkdir(directory, { recursive: false, mode: 0o700 })
  else await stat(join(directory, 'agent.sqlite')) // A lost volume must never become a new history implicitly.
  const store = new NativeAgentStore(join(directory, 'agent.sqlite'))
  const control = new NodeStateDatabase(join(directory, 'control.sqlite'))
  let armed = false
  let targetPayloadKey: string | undefined
  let targetRecordCommitted = false, targetClosureCommitted = false
  const authorityStore: DurableOperationStore = {
    get: key => store.get(key),
    async put(key, bytes) {
      const payload = key.startsWith('agent/authority/') && key.includes('/payload/')
      const record = key.startsWith('record-log/')
      const certificate = key.startsWith('agent/authority/') && key.endsWith('/certificate')
      // serve() may still replay old duplicate payloads/certificates. Trigger
      // only after the new operation's first distinct detached payload arrives.
      if (armed && payload && targetPayloadKey === undefined && await store.get(key) === null) targetPayloadKey = key
      const targetPayload = armed && payload && key === targetPayloadKey
      let targetRecord = false, targetClosure = false
      if (armed && targetPayloadKey !== undefined && record) {
        const encoded = assertCanonicalCbor(bytes)
        assert(Array.isArray(encoded) && encoded.at(-1) instanceof Uint8Array)
        const tail = decodeOrderingEvidence(encoded.at(-1) as Uint8Array)
        assert.equal(tail.kind, 'ordered-entry')
        if (tail.kind === 'ordered-entry') {
          targetClosure = targetRecordCommitted && isFinalityClosureRecord(tail.entry.bytes)
          if (!isFinalityClosureRecord(tail.entry.bytes)) {
            const descriptor = decodeLedgerRecord(tail.entry.bytes)
            targetRecord = descriptor.kind === 'candidate' && targetPayloadKey.endsWith(`/payload/${descriptor.payloadHash}`)
          }
        }
      }
      if (targetPayload) options.fault?.('before_payload_commit')
      if (targetRecord) options.fault?.('before_record_commit')
      if (targetClosure) options.fault?.('before_closure_commit')
      if (armed && targetClosureCommitted && certificate) options.fault?.('before_certificate_commit')
      await store.put(key, bytes)
      if (targetPayload) options.fault?.('after_payload_commit')
      if (targetRecord) { targetRecordCommitted = true; options.fault?.('after_record_commit') }
      if (targetClosure) { targetClosureCommitted = true; options.fault?.('after_closure_commit') }
      if (armed && targetClosureCommitted && certificate) options.fault?.('after_certificate_commit')
    },
  }
  let governed: Awaited<ReturnType<typeof createGovernedNode>> | undefined
  let agent: Awaited<ReturnType<typeof createDaemonAgentRuntime>> | undefined
  let materializer: DeterministicMaterializer | undefined
  let transport: PortableFeedTransport | undefined
  try {
    const identity = await loadOrCreateEnrollmentIdentity(store, 'authority-recovery-drill')
    let privateBootstrap = await store.get('recovery-drill/bootstrap')
    if (privateBootstrap === null) {
      assert(options.create === true, 'RECOVERY_BOOTSTRAP_MISSING')
      privateBootstrap = crypto.getRandomValues(new Uint8Array(96))
      await store.put('recovery-drill/bootstrap', privateBootstrap)
    }
    assert.equal(privateBootstrap.length, 96)
    // This fixture isolates crash durability from CPU/scheduler latency. Both
    // author and finality clocks are durable and advance only after the local
    // retained backlog is included, so a slow test host cannot turn a recovery
    // scenario into an unrelated late-admission rejection.
    const clockKey = 'recovery-drill/clock'
    const encodedClock = await store.get(clockKey)
    assert(encodedClock !== null || options.create === true, 'RECOVERY_CLOCK_MISSING')
    const storedClock = encodedClock === null ? BigInt(Date.now()) : assertCanonicalCbor(encodedClock)
    assert(typeof storedClock === 'bigint' && storedClock >= 0n && storedClock <= BigInt(Number.MAX_SAFE_INTEGER), 'RECOVERY_CLOCK_INVALID')
    let clockNow = Number(storedClock)
    if (encodedClock === null) await store.put(clockKey, encodeCanonicalCbor(storedClock))
    const groupId = privateBootstrap.slice(0, 32), groupRoute = privateBootstrap.slice(32, 64)
    const executionManifest = createDoltLiteExecutionManifest()
    const { executionManifestDigest } = await executionManifestArtifacts(executionManifest)
    transport = new PortableFeedTransport({ store: await DurableFeedStore.open(store, webFeedCrypto), crypto: webFeedCrypto,
      signer: webFeedSigner(feedIdFromPublicKey(identity.signing.publicKeyBytes), identity.signing.privateKey) })
    const bootstrap = await loadOrCreateGovernanceBootstrap({ dataDirectory: directory, groupId, schemaId: executionManifestDigest,
      identity: identity.signing, transportAuthor: transport.identity, historyPolicy: 'coordinated',
      clockPolicy: { cutoffLagMs: 250n, maxFutureSkewMs: 30_000n, heartbeatIntervalMs: 25n } })
    materializer = await DeterministicMaterializer.open({ path: join(directory, 'application.db'), executionManifest,
      rootAdministrator: bootstrap.genesis.manifest.schemaAdminPublicKey })
    governed = await createGovernedNode({ genesis: bootstrap.genesis, groupRoute, identity: identity.signing, transport,
      clock: { now: () => clockNow },
      operationStore: store, controlStore: new ControlStore(new SqliteControlStorePersistence(control)),
      materialization: createDoltLiteMaterializationRuntime(materializer),
      recipient: { id: bootstrap.recipientId, privateKey: bootstrap.recipientPrivateKey },
      initialEpochContentKey: privateBootstrap.slice(64) })
    // Validate an independently retained continuity floor before starting any ordering loop.
    agent = await createDaemonAgentRuntime({ node: governed.node, identity: identity.signing,
      descriptor: governed.descriptor, store: authorityStore, transport,
      activeMembership: () => governed!.activeSnapshot,
      peerLinks: { local: transport.asLink(), attach: (link) => transport!.connect(link) },
      finalityClock: () => clockNow,
      ...(options.continuity === undefined ? {} : { continuity: options.continuity }) })
    assert(agent.finality !== null)
    const authority = agent.finality, node = governed.node, activeTransport = transport
    await governed.start()
    let serviceFailure: Error | undefined
    const running = agent.run()
    void running.catch((error: unknown) => { serviceFailure = error instanceof Error ? error : new Error('RECOVERY_SERVICE_FAILED', { cause: error }) })
    const healthy = () => { if (serviceFailure !== undefined) throw serviceFailure }
    let backlog: { readonly eligible: number; readonly included: number; readonly head: OrderedRecordHead } | undefined
    const backlogIncluded = async () => {
      const eligible = (await activeTransport.history()).filter(record => ['candidate', 'capability', 'epoch-manifest'].includes(decodeEnvelope(record.payload).messageType))
      const range = await authority.read({ limit: 256 })
      assert(!range.hasMore, 'RECOVERY_FIXTURE_RECEIPT_LIMIT')
      backlog = { eligible: eligible.length, included: range.entries.filter(entry => !isFinalityClosureRecord(entry.bytes)).length, head: range.head }
      return backlog.included === backlog.eligible
    }
    // The expiry regression deliberately advances this before inclusion. The
    // crash cases call it only after retaining the backlog they intend to test.
    const advanceFinalityClock = async (throughMs: bigint) => {
      const target = throughMs + bootstrap.genesis.manifest.clockPolicy.cutoffLagMs
      assert(throughMs >= 0n && target <= BigInt(Number.MAX_SAFE_INTEGER), 'RECOVERY_CLOCK_EXHAUSTED')
      const next = Math.max(clockNow, Number(target))
      await store.put(clockKey, encodeCanonicalCbor(BigInt(next)))
      clockNow = next
    }
    const advanceClock = () => advanceFinalityClock(BigInt(clockNow) + 1n)
    let pending: readonly string[] = []
    const settled = async () => {
      const next: string[] = []
      if (!governed!.governance.hasFinalizedEpoch(governed!.governance.cipherRing.current().epochId)) next.push('encryption-epoch')
      for (const kind of ['schema', 'accepted', 'rejected', 'after-backup', 'authority-offline'] as const) {
        const operation = await node.operation(`recovery-${kind}`)
        if (operation !== null && !operation.final) next.push(`recovery-${kind}`)
      }
      pending = next
      return pending.length === 0
    }
    const settle = async () => {
      try {
        await eventually(async () => {
          healthy()
          if (!await backlogIncluded()) return false
          await node.waitForIdle()
          if (await settled()) return true
          await advanceClock()
          return settled()
        }, 'RECOVERY_FIXTURE_NOT_SETTLED')
      } catch (error) {
        if (!(error instanceof Error) || error.message !== 'RECOVERY_FIXTURE_NOT_SETTLED') throw error
        throw new Error(`RECOVERY_FIXTURE_NOT_SETTLED:${recoveryJson({ clockNow, backlog, pending })}`, { cause: error })
      }
    }
    await settle()
    const terminal = async (operationId: string) => {
      try {
        await eventually(async () => {
          healthy()
          if ((await node.operation(operationId))?.final === true) return true
          if (await backlogIncluded()) await advanceClock()
          return (await node.operation(operationId))?.final === true
        }, 'RECOVERY_OPERATION_NOT_FINAL')
      } catch (error) {
        if (!(error instanceof Error) || error.message !== 'RECOVERY_OPERATION_NOT_FINAL') throw error
        throw new Error(`RECOVERY_OPERATION_NOT_FINAL:${recoveryJson({ clockNow, backlog,
          operation: await node.operation(operationId), node: await node.status() })}`, { cause: error })
      }
      const operation = await node.operation(operationId)
      assert(operation !== null && operation.final)
      return operation
    }
    const submit = async (kind: RecoveryOperation) => {
      const operationId = `recovery-${kind}`
      const receipt = await node.publish({ operationId, program: recoveryProgram(kind) })
      const outcome = await terminal(operationId)
      assert.equal(outcome.proposalId, receipt.txIdText)
      if (armed) options.fault?.('before_acknowledgement')
      return outcome
    }
    const inspect = async () => {
      await settle()
      const range = await authority.certifiedRead({ limit: 256 }), certificate = range.certificate
      assert(!range.hasMore, 'RECOVERY_FIXTURE_RECEIPT_LIMIT')
      await verifyPrefixCertificate(certificate, authority.configuration)
      const payloads = await Promise.all(range.entries.filter(entry => !isFinalityClosureRecord(entry.bytes)).map(async entry => {
        const descriptor = decodeLedgerRecord(entry.bytes)
        const body = descriptor.inlinePayload ?? await authority.getPayload(descriptor.payloadHash)
        return { position: entry.position, recordId: entry.recordId, kind: descriptor.kind, hash: descriptor.payloadHash,
          descriptorBytes: entry.bytes.length, payloadBytes: body?.length ?? null, detached: descriptor.inlinePayload === null }
      }))
      const receipts = range.entries.map(entry => ({ position: entry.position, root: entry.root, recordId: entry.recordId,
        kind: isFinalityClosureRecord(entry.bytes) ? 'closure' as const : decodeLedgerRecord(entry.bytes).kind }))
      return { head: { historyId: certificate.historyId, position: certificate.position, root: certificate.root },
        receipts, proposalCount: payloads.filter(payload => payload.kind === 'candidate').length,
        closedThroughMs: range.entries.filter(entry => isFinalityClosureRecord(entry.bytes))
          .map(entry => decodeFinalityClosureRecord(entry.bytes).closedThroughMs).at(-1) ?? -1n,
        authorityIdentity: bytesToBase64Url(identity.signing.publicKeyBytes),
        executionManifestDigest: bytesToHex(executionManifestDigest),
        certificate: { historyId: certificate.historyId, position: certificate.position, root: certificate.root,
          signature: bytesToBase64Url(certificate.signature), configuration: bytesToBase64Url(certificate.configuration) },
        feed: { identity: activeTransport.identity, records: (await activeTransport.history()).map(record => ({ id: record.id, sequence: String(record.sequence) })) },
        operations: Object.fromEntries(await Promise.all(['schema', 'accepted', 'rejected', 'after-backup', 'authority-offline']
          .map(async kind => [kind, await node.operation(`recovery-${kind}`)] as const))),
        rows: node.localSql('SELECT id, value FROM recovery_probe ORDER BY id', [], { view: 'final' }).rows,
        events: (await node.events.read()).transactions,
        payloads, retainedValueBytes: store.usageBytes() }
    }
    return { store, node, authority, transport: activeTransport, agent, governed, identity, advanceFinalityClock,
      arm() { armed = true },
      async initialize() {
        const receipt = await node.publish({ operationId: 'recovery-schema', program: program(
          'CREATE TABLE recovery_probe (id INTEGER PRIMARY KEY, value INTEGER NOT NULL) STRICT',
          'INSERT INTO recovery_probe (id, value) VALUES (1, 10)',
        ) })
        assert.equal((await terminal('recovery-schema')).proposalId, receipt.txIdText)
        await settle()
      },
      submit, terminal, inspect, settle, advanceClock,
      async close() {
        await agent!.close()
        try { await governed!.close() } finally { control.close(); store.close() }
      },
    }
  } catch (error) {
    await agent?.close().catch(() => undefined)
    if (governed !== undefined) await governed.close().catch(() => undefined)
    else { materializer?.close(); await transport?.close().catch(() => undefined) }
    control.close(); store.close()
    throw error
  }
}

/** Read the post-crash disk before starting inclusion/finality or replay loops. */
export async function inspectStoppedAuthority(directory: string) {
  const document = JSON.parse(await readFile(join(directory, 'governance.json'), 'utf8')) as { signedGenesis: string }
  const genesis = decodeSignedGenesis(Uint8Array.from(Buffer.from(document.signedGenesis, 'base64')))
  assert(await verifySignedGenesis(genesis), 'RECOVERY_GENESIS_INVALID')
  const policy = genesis.manifest.historyPolicy
  assert(policy?.kind === 'coordinated' && policy.historyId !== undefined && policy.authorityPublicKey !== undefined)
  assert.deepEqual(policy.executionManifestDigest, genesis.manifest.schemaId)
  const historyId = policy.historyId
  const configuration: CoordinatedHistoryConfiguration = { kind: 'coordinated', historyId, authorityPublicKey: policy.authorityPublicKey,
    groupId: genesis.manifest.groupId, genesisDigest: await hashDomain(DOMAINS.genesis, encodeGenesisManifest(genesis.manifest)),
    executionManifestDigest: policy.executionManifestDigest,
    ...(policy.providerId === undefined ? {} : { providerId: policy.providerId }),
    ...(policy.providerParameters === undefined ? {} : { providerParameters: policy.providerParameters }) }
  const store = new NativeAgentStore(join(directory, 'agent.sqlite'))
  try {
    const log = await ReferenceRecordLog.open(historyId, store, { requireExisting: true })
    const entries = await log.read(), saved = await store.get(`agent/authority/${historyId}/certificate`)
    // Authenticate every retained closure, including a suffix committed after
    // the last certificate. An interrupted certificate write must not turn that
    // suffix into trusted finality or allow its signed prefix to be rewritten.
    const snapshot = await evaluateFinalitySnapshot(configuration, entries)
    const retainedClosures = entries.filter(entry => isFinalityClosureRecord(entry.bytes))
    assert.equal(snapshot.closures.length, retainedClosures.length, 'RECOVERY_UNAUTHENTICATED_CLOSURE')
    const certificate = saved === null ? null : decodeOrderingEvidence(saved)
    if (certificate !== null) {
      assert.equal(certificate.kind, 'prefix-certificate')
      if (certificate.kind === 'prefix-certificate') {
        await verifyPrefixCertificate(certificate.certificate, configuration)
        const prefix = certificate.certificate
        assert(prefix.position <= entries.length, 'RECOVERY_CERTIFICATE_AHEAD_OF_RETAINED_LOG')
        assert.equal(prefix.root, prefix.position === 0 ? await orderedGenesisRoot(historyId) : entries[prefix.position - 1]?.root,
          'RECOVERY_CERTIFICATE_PREFIX_MISMATCH')
      }
    }
    return { head: await log.head(), entries: entries.map(entry => ({ position: entry.position, root: entry.root, recordId: entry.recordId,
      kind: isFinalityClosureRecord(entry.bytes) ? 'closure' as const : decodeLedgerRecord(entry.bytes).kind })),
      closures: retainedClosures.map(entry => ({
        position: entry.position, ...decodeFinalityClosureRecord(entry.bytes),
      })),
      proposalCount: entries.filter(entry => !isFinalityClosureRecord(entry.bytes) && decodeLedgerRecord(entry.bytes).kind === 'candidate').length,
      certificate }
  } finally { store.close() }
}

/** The inspector has authenticated this certificate and all retained records. */
export function certifiedRecoveryFloor(raw: Awaited<ReturnType<typeof inspectStoppedAuthority>>, targetClosure: { readonly position: number },
  point: 'after_certificate_commit' | 'before_acknowledgement'): OrderedRecordHead {
  assert(raw.certificate?.kind === 'prefix-certificate', 'RECOVERY_CERTIFICATE_MISSING')
  const certificate = raw.certificate.certificate
  assert(certificate.position >= targetClosure.position, 'RECOVERY_TARGET_CLOSURE_NOT_CERTIFIED')
  assert.equal(certificate.historyId, raw.head.historyId)
  assert.equal(certificate.root, raw.entries[certificate.position - 1]?.root, 'RECOVERY_CERTIFICATE_PREFIX_MISMATCH')
  const floor = { historyId: certificate.historyId, position: certificate.position, root: certificate.root }
  if (point === 'after_certificate_commit') assert.deepEqual(floor, raw.head)
  else {
    // Caller acknowledgement is outside the finality mutex. A later idle
    // closure can be durable while its certificate write is still pending.
    // This isolated fixture has no other application/control publisher.
    assert(raw.entries.slice(certificate.position).every(entry => entry.kind === 'closure'), 'RECOVERY_UNEXPECTED_UNCERTIFIED_SUFFIX')
  }
  return floor
}

export async function eventually(check: () => boolean | Promise<boolean>, label: string, timeoutMs = 15_000) {
  const deadline = Date.now() + timeoutMs
  while (!await check()) {
    if (Date.now() > deadline) throw new Error(label)
    await new Promise(resolve => setTimeout(resolve, 10))
  }
}

export function recoveryJson(value: unknown): string {
  return JSON.stringify(value, (_key, item: unknown) => typeof item === 'bigint' ? item.toString() : item)
}

