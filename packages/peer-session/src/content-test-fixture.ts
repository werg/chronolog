import { afterEach } from 'vitest'
import type { BytesStore } from '@chronolog/records'
import { createEventMaterializationRuntime, eventExecutionManifest } from '@chronolog/materializer'
import { bytesToHex, executionManifestArtifacts } from '@chronolog/protocol'
import {
  bytesDigest, createGenerationRegistry, createPeerIdentity, createPeerReplica, MemoryBytesStore, participantGrant,
  signApplicationDescriptor, signControlRevision, signTransitionRequest, type PeerReplica,
} from '@chronolog/peer-generation'
import { ApplicationContent, type ContentReference } from './content.js'

const peers: PeerReplica[] = [], contents: ApplicationContent[] = []
afterEach(async () => { for (const content of contents.splice(0)) content.close(); for (const peer of peers.splice(0)) await peer.close() })
export async function fixture() {
  const host = await createPeerIdentity(), a = await createPeerIdentity(), b = await createPeerIdentity(), outsider = await createPeerIdentity()
  const key = crypto.getRandomValues(new Uint8Array(32)), keys = new Map([[0, key]])
  const manifest = await executionManifestArtifacts(await eventExecutionManifest())
  const descriptor = await signApplicationDescriptor({ applicationId: '45'.repeat(32), historyId: 'content-test',
    profile: 'peer-generation-v1', policy: 'eligible-members-v1', controlPublicKey: host.publicKey, schemaAdministrator: a.publicKey,
    executionManifestDigest: bytesToHex(manifest.executionManifestDigest), definitionDigest: '01'.repeat(32), schemaDigest: null }, host)
  const control = await signControlRevision({ applicationId: descriptor.payload.applicationId, profile: descriptor.payload.profile,
    policy: descriptor.payload.policy, revision: 0, previous: null, epoch: 0, keyDigest: await bytesDigest(key), recoveryFloor: null,
    grants: [participantGrant(a.publicKey, { administrator: true }), participantGrant(b.publicKey)] }, host)
  const registry = await createGenerationRegistry({ store: new MemoryBytesStore(), descriptor, controls: [control], signer: host })
  await registry.select(await signTransitionRequest({ applicationId: descriptor.payload.applicationId, profile: descriptor.payload.profile,
    policy: descriptor.payload.policy, transitionId: 'initial', expectedGeneration: null, coordinator: a.publicKey,
    requester: a.publicKey, controlRevision: 0, reason: 'create', base: null }, a))
  const stores = [new MemoryBytesStore(), new MemoryBytesStore()]
  const opened = await Promise.all([a, b].map(async (device, index) => {
    const store = stores[index]!, materializer = await createEventMaterializationRuntime({ store, namespace: 'content' })
    const peer = await createPeerReplica({ authority: await registry.read(), device, store, storageId: device.publicKey, materializer, epochKeys: keys })
    peers.push(peer); return peer
  }))
  const openContent = (index: number, store: BytesStore = stores[index]!) => {
    const content = new ApplicationContent({ replica: opened[index]!, store, storageId: [a, b][index]!.publicKey, epochKeys: keys })
    contents.push(content); return content
  }
  return { host, a, b, outsider, keys, control, registry, peers: opened, stores, openContent }
}
export async function collect(content: ApplicationContent, ref: ContentReference, options: { offset?: number; length?: number; signal?: AbortSignal } = {}): Promise<Uint8Array> {
  const pieces: Uint8Array[] = []
  for await (const bytes of content.read(ref, options)) pieces.push(bytes)
  const output = new Uint8Array(pieces.reduce((length, bytes) => length + bytes.length, 0))
  let offset = 0
  for (const piece of pieces) { output.set(piece, offset); offset += piece.length }
  return output
}
export function deferred<T>() {
  let resolve!: (value: T) => void
  const promise = new Promise<T>(done => { resolve = done })
  return { promise, resolve }
}
