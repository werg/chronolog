import { describe, expect, it, vi } from 'vitest'

import type { CapabilitySnapshot, SignedCapabilityRevision } from '@chronolog/capabilities'
import type { CapabilityChange, GovernanceControlPlane } from '@chronolog/node-core'
import type { GrantCapabilityRequest } from '@chronolog/rpc'

import { createGovernanceRpcAdmin } from './governance-admin.js'

describe('governance admin RPC adapter', () => {
  it('reports a stable public capability inventory and delegates a bounded grant', async () => {
    const snapshot = capabilitySnapshot()
    const publishCapabilityChange = vi.fn(async (change: CapabilityChange): Promise<SignedCapabilityRevision> => ({
      revision: { encryptionEpoch: 0n,
        groupId: snapshot.groupId,
        revision: 4n,
        previousRevisionDigest: snapshot.revisionDigest,
        issuerRootPublicKey: snapshot.rootAdminPublicKey,
        grants: (change.grants ?? []).map((grant) => ({ ...grant, validFromRevision: 4n })),
        revocations: [],
        validationPolicies: [],
      },
      signature: bytes(99),
    }))
    const governance = {
      snapshot,
      currentEpoch: 7n,
      publishCapabilityChange,
    } as unknown as GovernanceControlPlane
    const admin = createGovernanceRpcAdmin({ governance, rootPrivateKey: {} as CryptoKey, now: () => 12_345 })

    const status = await admin.getStatus({ groupId: b64(snapshot.groupId), requestId: 'status' })
    expect(status).toMatchObject({ revision: '3', currentEpoch: '7' })
    expect(status.capabilities).toEqual([expect.objectContaining({ role: 'writer', active: true,
      program: { sql: false, topics: ['requests'], signals: ['progress'], forwarded: false } })])

    const response = await admin.grantCapability({
      groupId: b64(snapshot.groupId),
      requestId: 'grant',
      subjectId: b64(bytes(20)),
      signingPublicKey: b64(bytes(21)),
      transportAuthor: 'new-node-feed',
      role: 'writer',
      program: { sql: false, topics: ['jobs'], signals: ['progress'] },
    })
    expect(response.revision).toBe('4')
    expect(Buffer.from(response.capabilityId, 'base64url')).toHaveLength(32)
    expect(publishCapabilityChange).toHaveBeenCalledWith({ grants: [expect.objectContaining({
      role: 'writer',
      program: { sql: false, topics: ['jobs'], signals: ['progress'], forwarded: false },
    })] }, expect.anything(), { operationId: 'grant' })
  })

  it('rejects ambiguous keys and invalid reader grants', async () => {
    const governance = { snapshot: capabilitySnapshot(), currentEpoch: null } as unknown as GovernanceControlPlane
    const admin = createGovernanceRpcAdmin({ governance, rootPrivateKey: {} as CryptoKey })
    const base = { groupId: b64(governance.snapshot.groupId), requestId: 'grant' }
    const common = { ...base, subjectId: b64(bytes(20)), signingPublicKey: b64(bytes(21)) }

    await expect(admin.grantCapability({ ...common, role: 'reader' })).rejects.toMatchObject({ code: 'invalid_argument' })
    const writer = { ...common, role: 'writer' as const, program: { sql: true, topics: [], signals: [] } }
    await expect(admin.grantCapability({ ...writer, signingPublicKey: 'not base64!' })).rejects.toMatchObject({ code: 'invalid_argument' })
    await expect(admin.grantCapability({ ...writer, hpkePublicKey: b64(bytes(22)) })).rejects.toMatchObject({ code: 'invalid_argument' })
    await expect(admin.grantCapability({ ...common, role: 'writer' } as unknown as GrantCapabilityRequest))
      .rejects.toMatchObject({ code: 'invalid_argument' })
    await expect(admin.grantCapability({ ...common, role: 'administrator' } as unknown as GrantCapabilityRequest))
      .rejects.toMatchObject({ code: 'invalid_argument' })
  })
})

function capabilitySnapshot(): CapabilitySnapshot {
  const id = bytes(8)
  return { encryptionEpoch: 0n,
    groupId: bytes(1),
    revision: 3n,
    revisionDigest: bytes(2),
    rootAdminPublicKey: bytes(3),
    capabilityLogFeed: new TextEncoder().encode('admin-feed'),
    capabilities: new Map([[b64(id), {
      id,
      grant: {
        subjectId: bytes(4),
        signingPublicKey: bytes(4),
        transportAuthor: 'admin-feed',
        role: 'writer',
        program: { sql: false, topics: ['requests'], signals: ['progress'] },
        validFromRevision: 0n,
      },
      grantedAtRevision: 0n,
    }]]),
    policies: new Map(),
    validatorFloorMs: 0n,
  }
}

function bytes(seed: number): Uint8Array {
  return Uint8Array.from({ length: 32 }, (_value, index) => (seed + index) & 0xff)
}
function b64(value: Uint8Array): string { return Buffer.from(value).toString('base64url') }
