import type { AuthorityProvider, AuthorityBundle } from './control.js'
import type { FinalityProof } from './finality.js'
import type { PublicationRegistry, SignedPublication } from './publication.js'
import { check, signRecord, verifyRecord, type Signed, type SigningIdentity } from './codec.js'
export interface ParticipantRequest {
  readonly applicationId: string
  readonly requestId: string
  readonly action: 'authority.read' | 'publication.read' | 'publication.publish' | 'finality.read' | 'finality.publish'
  readonly publication?: SignedPublication
  readonly proof?: FinalityProof
}
export type SignedParticipantRequest = Signed<ParticipantRequest>
export interface ParticipantResponse { readonly requestId: string; readonly authority?: AuthorityBundle; readonly publications?: readonly SignedPublication[]; readonly proofs?: readonly FinalityProof[] }
export async function signParticipantRequest(value: ParticipantRequest, identity: SigningIdentity): Promise<SignedParticipantRequest> { return signRecord('participant-request', value, identity) }
/** Portable thin control participant. It receives no epoch keys and never supplies application order. */
export function createAuthorityParticipant(options: { readonly authority: AuthorityProvider; readonly publications: PublicationRegistry; readonly finality?: { read(): Promise<readonly FinalityProof[]>; publish(proof: FinalityProof): Promise<void> } }): { handle(request: SignedParticipantRequest): Promise<ParticipantResponse> } {
  return { async handle(request) {
    await verifyRecord('participant-request', request)
    const value = request.payload, grant = options.authority.grant(request.signer)
    check(value.applicationId === options.authority.descriptor.applicationId && typeof value.requestId === 'string' && value.requestId.length > 0 && value.requestId.length <= 128 && grant !== null, 'PARTICIPANT_FORBIDDEN')
    switch (value.action) {
      case 'authority.read': return { requestId: value.requestId, authority: options.authority.bundle() }
      case 'publication.read': return { requestId: value.requestId, publications: await options.publications.read() }
      case 'publication.publish': check(grant.publisher && value.publication !== undefined && value.publication.signer === request.signer, 'PARTICIPANT_PUBLISHER_REQUIRED'); await options.publications.publish(value.publication); return { requestId: value.requestId }
      case 'finality.read': check(options.finality !== undefined, 'FINALITY_UNSUPPORTED'); return { requestId: value.requestId, proofs: await options.finality.read() }
      case 'finality.publish': check(grant.finalizer && options.finality !== undefined && value.proof !== undefined, 'PARTICIPANT_FINALIZER_REQUIRED'); await options.finality.publish(value.proof); return { requestId: value.requestId }
      default: throw new Error('PARTICIPANT_ACTION_UNSUPPORTED')
    }
  } }
}
