import { decodeSignedGenesis, encodeSignedGenesis, signGenesis } from '@chronolog/capabilities'
import { assertCanonicalCbor, bytesToBase64Url, decodeExecutionManifest, encodeCanonicalCbor, executionManifestArtifacts } from '@chronolog/protocol'
import { BrowserControlPersistence, WasmDatabase, openBrowserPeer, serveBrowserPeer,
  type BrowserPeer, type ChronologWasmModule, type WorkerEndpoint } from '@chronolog/runtime-browser'

const endpoint = globalThis as unknown as WorkerEndpoint
const groupId = new Uint8Array(32).fill(71)
let peer: BrowserPeer | undefined
let now = 1_700_000_000_000
let pauseOperation: string | null = null
let pauseApplication = false
let persistClock: (() => Promise<void>) | undefined
let engineModule: ChronologWasmModule | undefined

endpoint.addEventListener('message', (event) => {
  const request = event.data as { fixture?: string; id?: number; name?: string; createIdentity?: true; operationId?: string; cutoff?: string }
  if (request.fixture === undefined) return
  const run = async (): Promise<unknown> => {
    switch (request.fixture) {
      case 'open': {
        peer = await openBrowserPeer({
          name: request.name!, ...(request.createIdentity === true ? { createIdentity: true } : {}), engineUrl: new URL('/engine/', globalThis.location.href),
          async configure(context) {
            engineModule = context.engine.module
            const savedClock = await context.operations.get('fixture/clock')
            if (savedClock !== null) now = Number(assertCanonicalCbor(savedClock))
            persistClock = () => context.operations.put('fixture/clock', encodeCanonicalCbor(BigInt(now)))
            await persistClock()
            const response = await fetch('/execution-manifest.cbor')
            const executionManifest = decodeExecutionManifest(new Uint8Array(await response.arrayBuffer()))
            const { executionManifestDigest } = await executionManifestArtifacts(executionManifest)
            const originalPut = context.operations.put.bind(context.operations)
            context.operations.put = async (key, bytes) => {
              await originalPut(key, bytes)
              if (pauseOperation !== null && key.startsWith('transactions/') && key.endsWith('/pending')) {
                const saved = assertCanonicalCbor(bytes)
                if (Array.isArray(saved) && saved[0] === 1n) {
                  const prepared = assertCanonicalCbor(saved[3] as Uint8Array)
                  endpoint.postMessage({ fixture: 'paused', point: 'prepared', canonical: bytesToBase64Url((prepared as Uint8Array[])[0]!) })
                  await new Promise<void>(() => { /* The test terminates the actual Worker here. */ })
                }
              }
            }
            let savedGenesis = await context.operations.get('fixture/genesis')
            if (savedGenesis === null) {
              const common = { subjectId: context.identity.signing.publicKeyBytes, signingPublicKey: context.identity.signing.publicKeyBytes,
                transportAuthor: context.transport.identity, validFromRevision: 0n }
              const genesis = await signGenesis({
                groupId, schemaId: executionManifestDigest, historyPolicy: { kind: 'peer', executionManifestDigest },
                rootAdminPublicKey: context.identity.signing.publicKeyBytes, schemaAdminPublicKey: context.identity.signing.publicKeyBytes,
                capabilityLogFeed: new TextEncoder().encode(context.transport.identity),
                initialCapabilities: [
                  { ...common, role: 'administrator' }, { ...common, role: 'writer',
                    program: { sql: true, topics: ['notes.changed'], signals: [] } },
                  { ...common, role: 'validator', minimumAuthorTimestampMs: 0n },
                  { ...common, role: 'reader', hpkePublicKey: context.identity.reader.publicKeyBytes },
                ],
                validationPolicies: [{ version: 1n, minimumValidators: 1n }],
                clockPolicy: { maxFutureSkewMs: 30_000n, cutoffLagMs: 10n, heartbeatIntervalMs: 30_000n },
                resourcePolicy: { maxCandidateBytes: 16_000_000n, maxProgramNodes: 10_000n, maxPreconditions: 1_000n, maxMutations: 1_000n },
                encryptionSuite: 'HPKE-X25519-HKDF-SHA256-AES-256-GCM', createdAtMs: 1n,
              }, context.identity.signing.privateKey)
              savedGenesis = encodeSignedGenesis(genesis)
              await context.operations.put('fixture/genesis', savedGenesis)
            }
            const genesis = decodeSignedGenesis(savedGenesis)
            return {
              materializer: {
                executionManifest, rootAdministrator: genesis.manifest.schemaAdminPublicKey, checkpointEvery: 1,
                publicationFaultInjector(point) {
                  if (!pauseApplication || point !== 'after_candidate_commit') return
                  endpoint.postMessage({ fixture: 'paused', point })
                  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0)
                },
              },
              governed: { genesis, groupRoute: new Uint8Array(32).fill(72), clock: { now: () => now },
                initialEpochContentKey: new Uint8Array(32).fill(73) },
            }
          },
        })
        serveBrowserPeer(endpoint, peer)
        return { groupId: bytesToBase64Url(groupId), identity: bytesToBase64Url(peer.node.identity) }
      }
      case 'state': {
        await peer!.node.waitForIdle()
        return {
          identity: bytesToBase64Url(peer!.node.identity), hash: peer!.materializer.databaseContentHash,
          revision: String(peer!.materializer.revision), finalRevision: String(peer!.materializer.finalRevision),
          records: (await peer!.transport.asLink().read(peer!.transport.identity, 0n, 1_000)).map(bytesToBase64Url),
          transactions: peer!.materializer.transactionLog().map((row) => ({
            txId: bytesToBase64Url(row.txId), canonical: bytesToBase64Url(row.canonicalCandidate), sequence: String(row.authorFeedSequence),
          })),
        }
      }
      case 'advanceFinal': now += 1000; await persistClock!(); await peer!.node.publishHeartbeat(); await peer!.node.waitForIdle(); return null
      case 'privateCutoff': {
        // A private cutoff with no corresponding feed record must persist by
        // its own SQL commit. Replay cannot reconstruct this test value.
        const control = new BrowserControlPersistence(new WasmDatabase(engineModule!, '/private-cutoff-probe.db'))
        try {
          if (request.cutoff !== undefined) control.saveValidatorCutoff({ validatorId: peer!.node.identity, acceptedAboveMs: BigInt(request.cutoff) })
          return control.loadValidatorCutoffs().map((value) => String(value.acceptedAboveMs))
        } finally { control.close() }
      }
      case 'armPrepared': pauseOperation = request.operationId!; return null
      case 'armApplication': pauseApplication = true; return null
      default: throw new Error('UNKNOWN_TEST_COMMAND')
    }
  }
  void run().then((value) => endpoint.postMessage({ fixture: 'response', id: request.id, value }),
    (error: unknown) => endpoint.postMessage({ fixture: 'response', id: request.id, error: error instanceof Error ? error.stack : String(error) }))
})
