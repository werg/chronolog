import { bytesToHex } from '@chronolog/canonical'
import type { AdmissionEvidence, SigningIdentity } from '@chronolog/authority'
import type { QuickJsSandboxOptions } from '@chronolog/materializer'
import {
  decodeEncryptedEnvelope,
  decodeSignedOperation,
  encryptedEnvelopeDigest,
  operationIdDigest,
} from '@chronolog/protocol'
import { MemoryBytesStore } from '@chronolog/records'
import { openApplicationDevice } from './device.js'
import { createApplicationSession } from './runtime.js'
import type { ApplicationSession, SessionCasNode } from './session.js'

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
  const existingPublicOpIds = new Set<string>()
  for (const raw of options.publicOps) {
    try {
      const signed = decodeSignedOperation(raw)
      existingPublicOpIds.add(bytesToHex(operationIdDigest(signed.coreBytes)))
    } catch { /* ignore */ }
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
  const newSealedPrivateCas: HostedSealedCasItem[] = []
  const prunedPrivateCasHashes: string[] = []
  let snapshot: Uint8Array | null = null

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
    value = await work(session)

    const exported = await session.exportFacts()
    for (const rawEnv of exported.encryptedEnvelopes) {
      const digest = bytesToHex(encryptedEnvelopeDigest(rawEnv))
      if (!hydratedEnvDigests.has(digest)) {
        const decoded = decodeEncryptedEnvelope(rawEnv)
        newEnvelopes.push({
          digest,
          epoch: decoded.epoch,
          author: bytesToHex(decoded.author),
          raw: rawEnv,
        })
        hydratedEnvDigests.add(digest)
      }
    }
    for (const rawOp of exported.publicOps) {
      try {
        const signed = decodeSignedOperation(rawOp)
        const opId = bytesToHex(operationIdDigest(signed.coreBytes))
        if (!existingPublicOpIds.has(opId)) {
          newPublicOps.push(rawOp)
          existingPublicOpIds.add(opId)
        }
      } catch { /* ignore */ }
    }

    const activePrivHashes = new Set<string>()
    for (const node of exported.casNodes) {
      if (node.partition !== 'private') continue
      activePrivHashes.add(node.hash)
      if (!hydratedPrivHashes.has(node.hash) && options.sealPrivateCas !== undefined) {
        const sealed = await options.sealPrivateCas(node.hash, node.bytes)
        newSealedPrivateCas.push({ hash: node.hash, sealed })
        hydratedPrivHashes.add(node.hash)
      }
    }
    for (const oldHash of hydratedPrivHashes) {
      if (!activePrivHashes.has(oldHash)) prunedPrivateCasHashes.push(oldHash)
    }

    const exportedSnap = await session.exportMaterializedSnapshot()
    if (exportedSnap !== null && exportedSnap.byteLength <= maxSnapshotBytes) {
      snapshot = exportedSnap
    }
  } finally {
    try { await session.close() } catch { /* ignore */ }
    for (const key of epochKeys.values()) key.fill(0)
    epochKeys.clear()
  }

  return {
    value,
    delta: {
      newEnvelopes,
      newPublicOps,
      newSealedPrivateCas,
      prunedPrivateCasHashes,
      snapshot,
    },
  }
}
