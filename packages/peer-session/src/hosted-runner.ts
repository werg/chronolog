import { bytesToHex } from '@chronolog/canonical'
import type { AdmissionEvidence, SigningIdentity } from '@chronolog/authority'
import type { QuickJsSandboxOptions } from '@chronolog/materializer'
import { decodeEncryptedEnvelope, encryptedEnvelopeDigest } from '@chronolog/protocol'
import { MemoryBytesStore } from '@chronolog/records'
import { openApplicationDevice } from './device.js'
import { createApplicationSession } from './runtime.js'
import type { ApplicationSession, SessionCasNode } from './session.js'
import { standardModuleHashes } from './standard-modules.js'

export interface HostedEncryptedEnvelopeExport {
  readonly digest: string
  readonly epoch: number
  readonly author: string
  readonly raw: Uint8Array
}

export interface HostedSealedCasItem {
  readonly hash: string
  readonly sealed: Uint8Array
}

export interface RunEphemeralHostedSessionOptions {
  readonly genesisBytes: Uint8Array
  readonly signer: SigningIdentity
  readonly epochKeys: ReadonlyMap<number, Uint8Array>
  readonly publicOps: readonly Uint8Array[]
  readonly encryptedEnvelopes: readonly Uint8Array[]
  readonly publicCasNodes: readonly { readonly hash: string; readonly bytes: Uint8Array }[]
  readonly sealedPrivateCas?: readonly HostedSealedCasItem[]
  readonly evidence?: readonly AdmissionEvidence[]
  readonly materializedSnapshot?: Uint8Array
  readonly casMirrors?: readonly string[]
  readonly wasmModule?: QuickJsSandboxOptions['wasmModule']
  readonly sqliteWasmModule?: WebAssembly.Module
  readonly maxSnapshotBytes?: number
  readonly unsealPrivateCas?: (hash: string, sealed: Uint8Array) => Promise<Uint8Array | null>
  readonly sealPrivateCas?: (hash: string, plain: Uint8Array) => Promise<Uint8Array>
}

export interface EphemeralHostedSessionDelta {
  readonly newEnvelopes: readonly HostedEncryptedEnvelopeExport[]
  readonly newPublicOps: readonly Uint8Array[]
  readonly newPublicCasNodes: readonly { readonly hash: string; readonly bytes: Uint8Array }[]
  readonly newSealedPrivateCas: readonly HostedSealedCasItem[]
  readonly prunedPrivateCasHashes: readonly string[]
  readonly snapshot: Uint8Array | null
}

/**
 * Stateless, zero-plaintext-at-rest Chronolog session runner for Cloudflare Workers,
 * hosted MCP gateways, and serverless webhooks.
 *
 * Hydrates an ephemeral `MemoryBytesStore` `ApplicationSession` using caller-supplied
 * RAM-only `signer` and `epochKeys`, executes `work(session)`, exports only encrypted
 * delta envelopes, newly sealed private CAS nodes, pruned private CAS hashes, and an
 * opaque epoch-AEAD materialized snapshot, and zeroes/discards RAM keys in `finally`.
 *
 * The delta is tracked from the session's `onFacts` notifications during `work` (no re-export of
 * the whole log per request). `materializedSnapshot` must be a bundle this host produced itself
 * (a previous run's `delta.snapshot`): it is adopted without replaying the history it covers.
 */
export async function runEphemeralHostedSession<T>(
  options: RunEphemeralHostedSessionOptions,
  work: (session: ApplicationSession) => Promise<T>,
): Promise<{ readonly value: T; readonly delta: EphemeralHostedSessionDelta }> {
  const epochKeys = new Map<number, Uint8Array>()
  for (const [epoch, key] of options.epochKeys) epochKeys.set(epoch, key.slice())

  const memStore = new MemoryBytesStore()
  const device = await openApplicationDevice({
    store: memStore,
    managedSigner: options.signer,
    create: true,
  })

  const hydratedPubHashes = new Set<string>(standardModuleHashes())
  for (const n of options.publicCasNodes) hydratedPubHashes.add(n.hash)
  const casNodes: SessionCasNode[] = options.publicCasNodes.map(n => ({
    hash: n.hash,
    bytes: n.bytes,
    partition: 'public',
  }))
  const hydratedPrivHashes = new Set<string>()
  if (options.sealedPrivateCas !== undefined && options.unsealPrivateCas !== undefined) {
    for (const item of options.sealedPrivateCas) {
      const opened = await options.unsealPrivateCas(item.hash, item.sealed)
      if (opened !== null) {
        casNodes.push({ hash: item.hash, bytes: opened, partition: 'private' })
        hydratedPrivHashes.add(item.hash)
      }
    }
  }

  const hydratedEnvDigests = new Set<string>()
  for (const raw of options.encryptedEnvelopes) {
    hydratedEnvDigests.add(bytesToHex(encryptedEnvelopeDigest(raw)))
  }

  const session = await createApplicationSession({
    device,
    genesis: options.genesisBytes,
    casNodes,
    epochKeys,
    ...(options.materializedSnapshot === undefined ? {} : { materializedSnapshot: options.materializedSnapshot }),
    ...(options.casMirrors === undefined ? {} : { casMirrors: options.casMirrors }),
    ...(options.wasmModule === undefined ? {} : { wasmModule: options.wasmModule }),
    ...(options.sqliteWasmModule === undefined ? {} : { sqliteWasmModule: options.sqliteWasmModule }),
  })

  const maxSnapshotBytes = options.maxSnapshotBytes ?? 1024 * 1024
  let value!: T
  const newEnvelopes: HostedEncryptedEnvelopeExport[] = []
  const newPublicOps: Uint8Array[] = []
  const newPublicCasNodes: { readonly hash: string; readonly bytes: Uint8Array }[] = []
  const newSealedPrivateCas: HostedSealedCasItem[] = []
  const prunedPrivateCasHashes: string[] = []
  let snapshot: Uint8Array | null = null

  // Facts the session learns after hydration (authored by `work`, rewrapped, or merged by it).
  const touched = { public: new Set<string>(), private: new Set<string>() }
  let stopTracking: (() => void) | undefined
  try {
    if (options.publicOps.length > 0 || options.encryptedEnvelopes.length > 0 || (options.evidence?.length ?? 0) > 0) {
      await session.mergeFacts({
        publicOps: [...options.publicOps],
        encryptedEnvelopes: [...options.encryptedEnvelopes],
        casNodes,
        retentions: [],
        evidence: [...(options.evidence ?? [])],
      })
    }
    stopTracking = session.onFacts(delta => {
      for (const item of delta.items) touched[item.scope].add(item.id)
    })
    value = await work(session)
    stopTracking()
    stopTracking = undefined

    const privateFacts = session.exportFactsById('private', [...touched.private].filter(d => !hydratedEnvDigests.has(d)))
    for (const rawEnv of privateFacts.encryptedEnvelopes) {
      const digest = bytesToHex(encryptedEnvelopeDigest(rawEnv))
      const decoded = decodeEncryptedEnvelope(rawEnv)
      newEnvelopes.push({ digest, epoch: decoded.epoch, author: bytesToHex(decoded.author), raw: rawEnv })
      hydratedEnvDigests.add(digest)
    }
    // Ids in the public scope are op ids and evidence digests; hydrated public ops were merged
    // before tracking started, so every public op here is new.
    newPublicOps.push(...session.exportFactsById('public', [...touched.public]).publicOps)

    for (const hash of session.cas.listKnownHashes('public')) {
      if (hydratedPubHashes.has(hash)) continue
      const bytes = await session.cas.getRaw(hash, 'public')
      if (bytes !== null) newPublicCasNodes.push({ hash, bytes })
      hydratedPubHashes.add(hash)
    }
    // Private CAS is diffed against what the session's CAS still holds (not against an export,
    // which omits private nodes for non-reader runners and would prune everything).
    const activePrivHashes = new Set(session.cas.listKnownHashes('private'))
    for (const hash of activePrivHashes) {
      if (hydratedPrivHashes.has(hash) || options.sealPrivateCas === undefined) continue
      const bytes = await session.cas.getRaw(hash, 'private')
      if (bytes === null) continue
      newSealedPrivateCas.push({ hash, sealed: await options.sealPrivateCas(hash, bytes) })
      hydratedPrivHashes.add(hash)
    }
    for (const oldHash of hydratedPrivHashes) {
      if (!activePrivHashes.has(oldHash)) prunedPrivateCasHashes.push(oldHash)
    }

    const exportedSnap = await session.exportMaterializedSnapshot()
    if (exportedSnap !== null && exportedSnap.byteLength <= maxSnapshotBytes) {
      snapshot = exportedSnap
    }
  } finally {
    stopTracking?.()
    // close() zeroes the session's in-memory keys; then drop every persisted copy (epoch, ring,
    // vault keys, TreeKEM seeds, device wrap keys) from the RAM store before it is discarded.
    try { await session.close() } catch { /* ignore */ }
    try {
      const keys: string[] = []
      for await (const entry of memStore.iterateEntries()) { entry.value.fill(0); keys.push(entry.key) }
      await memStore.deleteMany(keys)
    } catch { /* ignore */ }
    for (const key of epochKeys.values()) key.fill(0)
    epochKeys.clear()
  }

  return {
    value,
    delta: {
      newEnvelopes,
      newPublicOps,
      newPublicCasNodes,
      newSealedPrivateCas,
      prunedPrivateCasHashes,
      snapshot,
    },
  }
}
