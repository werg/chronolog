import {
  controlParticipantGrant, createGenerationRegistry, createPeerIdentity, generationStartRoot, participantGrant, peerDigest,
  signApplicationDescriptor, signControlRevision, signTransitionRequest,
} from '@chronolog/peer-generation/control'
import { MemoryBytesStore } from '@chronolog/records'
import { describe, expect, it } from 'vitest'
import { signCelldWorkspacePublication, verifyCelldWorkspacePublication } from './celld-workspace-publication.js'

const transition = {
  sourceNodeId: 'a2'.repeat(32), destinationNodeId: 'b1'.repeat(32), workspaceId: 'ws_application',
  previousHead: 'c2'.repeat(20), proposedHead: 'd3'.repeat(20),
}

async function fixture() {
  const admin = await createPeerIdentity(), control = await createPeerIdentity(), publisher = await createPeerIdentity()
  const scope = { applicationId: 'a0'.repeat(32), profile: 'peer-generation-v1', policy: 'eligible-members-v1' } as const
  const descriptor = await signApplicationDescriptor({ ...scope, historyId: 'workspace-publication-fixture',
    schemaAdministrator: admin.publicKey, controlPublicKey: control.publicKey,
    definitionDigest: '12'.repeat(32), executionManifestDigest: '34'.repeat(32), schemaDigest: null }, control)
  const firstControl = await signControlRevision({ ...scope, revision: 0, previous: null, epoch: 0, keyDigest: '56'.repeat(32),
    recoveryFloor: null, grants: [controlParticipantGrant(control.publicKey), participantGrant(admin.publicKey, { administrator: true }),
      participantGrant(publisher.publicKey, { publisher: true })] }, control)
  const registry = await createGenerationRegistry({ store: new MemoryBytesStore(), descriptor, controls: [firstControl], signer: control })
  const initial = await registry.select(await signTransitionRequest({ ...scope, transitionId: 'create', expectedGeneration: null,
    requester: admin.publicKey, coordinator: admin.publicKey, controlRevision: 0, reason: 'create', base: null }, admin))
  return { admin, publisher, authority: await registry.read(), revoke: async () => {
    const nextControl = await signControlRevision({ ...firstControl.payload, revision: 1, previous: await peerDigest(firstControl),
      grants: firstControl.payload.grants.map(grant => grant.publicKey === publisher.publicKey ? { ...grant, publisher: false } : grant) }, control)
    const request = await signTransitionRequest({ ...scope, transitionId: 'revoke', expectedGeneration: initial.id,
      requester: control.publicKey, coordinator: admin.publicKey, controlRevision: 1, reason: 'control-change',
      base: { point: { generation: initial.id, sequence: 0, root: await generationStartRoot(initial) }, receipt: null, bridge: [] } }, control)
    await registry.select(request, { control: nextControl })
    return registry.read()
  } }
}

describe('celld workspace publication authority', () => {
  it('requires a publisher and proves the exact source, destination and both heads', async () => {
    const { admin, authority, publisher } = await fixture()
    await expect(signCelldWorkspacePublication({ authority, transition, publisher: admin }))
      .rejects.toThrow('CELLD_WORKSPACE_PUBLICATION_FORBIDDEN')
    const publication = await signCelldWorkspacePublication({ authority, transition, publisher })
    await expect(verifyCelldWorkspacePublication({ authority, transition, publication })).resolves.toBe(publisher.publicKey)
    for (const different of [
      { sourceNodeId: '11'.repeat(32) }, { destinationNodeId: 'ff'.repeat(32) }, { workspaceId: 'ws_other' },
      { previousHead: 'aa'.repeat(20) }, { proposedHead: 'ee'.repeat(20) },
    ]) {
      await expect(verifyCelldWorkspacePublication({ authority, transition: { ...transition, ...different }, publication }))
        .rejects.toThrow('CELLD_WORKSPACE_PUBLICATION_TRANSITION_MISMATCH')
    }
    const forged = { ...publication, payload: { ...publication.payload, proposedHead: 'ee'.repeat(20) } }
    await expect(verifyCelldWorkspacePublication({ authority, transition: { ...transition, proposedHead: forged.payload.proposedHead }, publication: forged }))
      .rejects.toThrow('CELLD_WORKSPACE_PUBLICATION_SIGNATURE_INVALID')
  })

  it('refuses a previously signed publication after the receiver advances authority', async () => {
    const { authority, publisher, revoke } = await fixture()
    const publication = await signCelldWorkspacePublication({ authority, transition, publisher })
    const current = await revoke()
    await expect(verifyCelldWorkspacePublication({ authority: current, transition, publication }))
      .rejects.toThrow('CELLD_WORKSPACE_PUBLICATION_AUTHORITY_CHANGED')
    await expect(signCelldWorkspacePublication({ authority: current, transition, publisher }))
      .rejects.toThrow('CELLD_WORKSPACE_PUBLICATION_FORBIDDEN')
  })
})
