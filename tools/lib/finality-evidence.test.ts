import { NativeFinalityService } from '@chronolog/agent-service'
import { signGenesis } from '@chronolog/capabilities'
import {
  CoordinatedHistoryPolicy, MemoryOperationStore, decodeOrderingEvidence, membershipDescriptor,
  type OrderingEvidence,
} from '@chronolog/node-core'
import { encodeEnvelope, generateEd25519KeyPair, utf8 } from '@chronolog/protocol'
import { feedIdFromPublicKey } from '@chronolog/records'
import { describe, expect, it } from 'vitest'

import { createFinalityEvidencePublisher } from './finality-evidence.js'

const groupId = new Uint8Array(32).fill(1)
const envelope = (text: string) => encodeEnvelope({ groupRoute: groupId, messageType: 'candidate', encryptionEpoch: null, payload: utf8(text) })

async function fixture() {
  const identity = await generateEd25519KeyPair(), schemaId = new Uint8Array(32).fill(2)
  const genesis = await signGenesis({ groupId, schemaId, rootAdminPublicKey: identity.publicKeyBytes,
    schemaAdminPublicKey: identity.publicKeyBytes, capabilityLogFeed: utf8(feedIdFromPublicKey(identity.publicKeyBytes)),
    historyPolicy: { kind: 'coordinated', historyId: 'h_0123456789abcdef0123456789abcdef',
      authorityPublicKey: identity.publicKeyBytes, executionManifestDigest: schemaId },
    initialCapabilities: [], validationPolicies: [{ version: 1n, minimumValidators: 1n }],
    clockPolicy: { cutoffLagMs: 0n, maxFutureSkewMs: 0n, heartbeatIntervalMs: 1_000n },
    resourcePolicy: { maxCandidateBytes: 1_000_000n, maxProgramNodes: 1_000n, maxPreconditions: 100n, maxMutations: 100n },
    encryptionSuite: 'HPKE-X25519-HKDF-SHA256-AES-256-GCM', createdAtMs: 1n,
  }, identity.privateKey)
  const descriptor = await membershipDescriptor(genesis, groupId)
  const finality = await NativeFinalityService.open({ descriptor, identity, store: new MemoryOperationStore(), now: () => 1_000 })
  for (let index = 0; index < 65; index += 1) await finality.append(envelope(`proposal-${index}`))
  const peer = await CoordinatedHistoryPolicy.open(finality.configuration, new MemoryOperationStore())
  return { finality, peer }
}

describe('manual finality evidence publication', () => {
  it('drains beyond one page to the captured certificate, then resumes and retries exact evidence after a lost reply', async () => {
    const { finality, peer } = await fixture()
    let certifications = 0, appended = false, loseReply = false
    const reads: Array<{ after?: number; limit?: number }> = [], received: OrderingEvidence[] = []
    const publish = createFinalityEvidencePublisher({ configuration: finality.configuration,
      async certifiedRead(options) { certifications += 1; return finality.certifiedRead(options) },
      async read(options) { reads.push({ ...options }); return finality.read(options) },
    }, { async putEvidence(bytes) {
      const evidence = decodeOrderingEvidence(bytes)
      received.push(evidence)
      await peer.ingest(evidence)
      // A concurrently appended record must wait for the next captured proof.
      if (!appended) { appended = true; await finality.append(envelope('next-publication')) }
      if (loseReply && evidence.kind === 'ordered-entry') { loseReply = false; throw new Error('lost evidence reply') }
    } })

    const first = await publish()
    expect(certifications).toBe(1)
    expect(first.position).toBe(66)
    expect(reads).toEqual([{ after: 64, limit: 2 }])
    expect(peer.progress.finalThrough).toBe(66)
    expect(received.at(-1)).toMatchObject({ kind: 'prefix-certificate', certificate: first })
    expect((await finality.head()).position).toBe(67)
    expect(received.filter(item => item.kind === 'ordered-entry').map(item => item.entry.position))
      .toEqual(Array.from({ length: 66 }, (_, index) => index + 1))

    received.length = 0
    loseReply = true
    await expect(publish()).rejects.toThrow('lost evidence reply')
    expect(peer.progress.finalThrough).toBe(66)
    const second = await publish()
    expect(certifications).toBe(3)
    expect(second).toEqual(await finality.head())
    expect(second.position).toBe(68)
    expect(peer.progress.finalThrough).toBe(68)
    expect(received.filter(item => item.kind === 'ordered-entry').map(item => item.entry.position)).toEqual([67, 67, 68])
    expect(received.at(-1)).toMatchObject({ kind: 'prefix-certificate', certificate: second })
  })

  it('refuses an incomplete page without publishing a certificate for missing receipts', async () => {
    const { finality, peer } = await fixture()
    const received: OrderingEvidence[] = []
    const publish = createFinalityEvidencePublisher({ configuration: finality.configuration,
      certifiedRead: options => finality.certifiedRead(options),
      async read(options) { return { ...await finality.read(options), entries: [] } },
    }, { async putEvidence(bytes) {
      const evidence = decodeOrderingEvidence(bytes)
      received.push(evidence)
      await peer.ingest(evidence)
    } })
    await expect(publish()).rejects.toThrow('FINALITY_PUBLICATION_NO_PROGRESS')
    expect(received).toHaveLength(64)
    expect(received.every(item => item.kind === 'ordered-entry')).toBe(true)
    expect(peer.progress.finalThrough).toBe(0)
  })
})
