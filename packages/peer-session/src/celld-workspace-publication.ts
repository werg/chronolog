import { encodePeerValue, verifyAuthorityBundle, type AuthorityBundle, type PeerIdentity } from '@chronolog/peer-generation/control'
import { bytesToHex, DOMAINS, hexToBytes, signDomain, verifyDomain } from '@chronolog/protocol'

/** The exact canonical ref transition between two authenticated workspace nodes. */
export interface CelldWorkspacePublication {
  readonly sourceNodeId: string
  readonly destinationNodeId: string
  readonly workspaceId: string
  readonly previousHead: string
  readonly proposedHead: string
}

interface WorkspacePublicationPayload extends CelldWorkspacePublication {
  readonly version: 1
  readonly applicationId: string
  readonly generation: string
  readonly publisherPublicKey: string
}

export interface SignedCelldWorkspacePublication {
  readonly payload: WorkspacePublicationPayload
  readonly signature: string
}

const publicationFields = ['sourceNodeId', 'destinationNodeId', 'workspaceId', 'previousHead', 'proposedHead'] as const
const payloadFields = ['version', 'applicationId', 'generation', 'publisherPublicKey', ...publicationFields] as const

function exactKeys(value: unknown, keys: readonly string[]): boolean {
  return value !== null && typeof value === 'object' && Object.keys(value).length === keys.length &&
    keys.every(key => Object.hasOwn(value, key))
}

function hex(value: unknown, length: number): value is string {
  return typeof value === 'string' && value.length === length && /^[0-9a-f]+$/u.test(value)
}

function validatePublication(value: CelldWorkspacePublication): void {
  if (!hex(value.sourceNodeId, 64) || !hex(value.destinationNodeId, 64) || value.sourceNodeId === value.destinationNodeId || typeof value.workspaceId !== 'string' ||
      !/^[a-zA-Z0-9_-]{1,128}$/u.test(value.workspaceId) ||
      !hex(value.previousHead, 40) || !hex(value.proposedHead, 40) || value.previousHead === value.proposedHead) {
    throw new Error('CELLD_WORKSPACE_PUBLICATION_TRANSITION_INVALID')
  }
}

/** Sign one named workspace's main transition as a publisher in the selected generation. */
export async function signCelldWorkspacePublication(input: {
  readonly authority: AuthorityBundle
  readonly transition: CelldWorkspacePublication
  readonly publisher: PeerIdentity
}): Promise<SignedCelldWorkspacePublication> {
  const transition = structuredClone(input.transition)
  if (!exactKeys(transition, publicationFields)) throw new Error('CELLD_WORKSPACE_PUBLICATION_TRANSITION_INVALID')
  validatePublication(transition)
  const publisher = { ...input.publisher }
  const authority = await verifyAuthorityBundle(structuredClone(input.authority))
  if (!authority.current) throw new Error('CELLD_WORKSPACE_PUBLICATION_GENERATION_REQUIRED')
  if (authority.grant(publisher.publicKey)?.publisher !== true) throw new Error('CELLD_WORKSPACE_PUBLICATION_FORBIDDEN')
  const payload: WorkspacePublicationPayload = {
    version: 1, applicationId: authority.bundle.descriptor.payload.applicationId,
    generation: authority.current.id, publisherPublicKey: publisher.publicKey, ...transition,
  }
  const signature = bytesToHex(await signDomain(DOMAINS.celldWorkspacePublication, encodePeerValue(payload), publisher.privateKey))
  return { payload, signature }
}

/** Verify against the receiver's selected authority and independently reviewed heads. */
export async function verifyCelldWorkspacePublication(input: {
  readonly authority: AuthorityBundle
  readonly transition: CelldWorkspacePublication
  readonly publication: SignedCelldWorkspacePublication
}): Promise<string> {
  const expected = structuredClone(input.transition)
  if (!exactKeys(expected, publicationFields)) throw new Error('CELLD_WORKSPACE_PUBLICATION_TRANSITION_INVALID')
  validatePublication(expected)
  const proof = structuredClone(input.publication)
  if (!exactKeys(proof, ['payload', 'signature']) || !hex(proof.signature, 128) ||
      !exactKeys(proof.payload, payloadFields)) throw new Error('CELLD_WORKSPACE_PUBLICATION_INVALID')
  const { payload, signature } = proof
  if (payload.version !== 1 || !hex(payload.publisherPublicKey, 64) ||
      publicationFields.some(field => payload[field] !== expected[field])) {
    throw new Error('CELLD_WORKSPACE_PUBLICATION_TRANSITION_MISMATCH')
  }
  const authority = await verifyAuthorityBundle(structuredClone(input.authority))
  if (payload.applicationId !== authority.bundle.descriptor.payload.applicationId ||
      !authority.current || payload.generation !== authority.current.id) {
    throw new Error('CELLD_WORKSPACE_PUBLICATION_AUTHORITY_CHANGED')
  }
  if (authority.grant(payload.publisherPublicKey)?.publisher !== true) throw new Error('CELLD_WORKSPACE_PUBLICATION_FORBIDDEN')
  const valid = await verifyDomain(DOMAINS.celldWorkspacePublication, encodePeerValue(payload),
    hexToBytes(signature), hexToBytes(payload.publisherPublicKey))
  if (!valid) throw new Error('CELLD_WORKSPACE_PUBLICATION_SIGNATURE_INVALID')
  return payload.publisherPublicKey
}
