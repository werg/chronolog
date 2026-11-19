import {
  encodePeerValue, verifyAuthorityBundle,
  type AuthorityBundle, type PeerAuthority, type PeerIdentity,
} from '@chronolog/peer-generation/control'
import { bytesToHex, DOMAINS, hexToBytes, signDomain, verifyDomain } from '@chronolog/protocol'

import type { CelldPeerEndpoint } from './celld-peer.js'
import type { ApplicationDevice } from './device.js'
import type { ApplicationPeerHint } from './participation-types.js'
import { retainApplicationAuthority } from './session-authority.js'

interface InvitationPayload {
  readonly version: 1
  readonly memberPublicKey: string
  readonly inviterPublicKey: string
  readonly generation: string
  readonly endpoint: CelldPeerEndpoint
  readonly authority: AuthorityBundle
}
export interface CelldApplicationInvitation {
  readonly payload: InvitationPayload
  readonly signature: string
}
export interface AcceptedCelldApplicationInvitation {
  readonly authority: AuthorityBundle
  readonly peer: ApplicationPeerHint
  readonly endpoint: CelldPeerEndpoint
}

function exactKeys(value: unknown, keys: readonly string[]): boolean {
  return value !== null && typeof value === 'object' && Object.keys(value).length === keys.length &&
    keys.every(key => Object.hasOwn(value, key))
}
function key(value: unknown): value is string {
  return typeof value === 'string' && /^[0-9a-f]{64}$/u.test(value)
}
function routeText(value: unknown): value is string {
  return typeof value === 'string' && value.length > 0 && value.length <= 512 &&
    [...value].every(character => character.charCodeAt(0) > 32 && character.charCodeAt(0) !== 127)
}
function validateEndpoint(endpoint: CelldPeerEndpoint): void {
  if (!endpoint || typeof endpoint !== 'object' || !key(endpoint.nodeId) ||
      Object.keys(endpoint).some(field => field !== 'nodeId' && field !== 'addrs' && field !== 'relay') ||
      endpoint.relay !== undefined && !routeText(endpoint.relay) ||
      endpoint.addrs !== undefined && (!Array.isArray(endpoint.addrs) || endpoint.addrs.length > 16 || !endpoint.addrs.every(routeText))) {
    throw new Error('CELLD_INVITATION_ENDPOINT_INVALID')
  }
}
function verifyMembers(authority: PeerAuthority, member: string, inviter: string): void {
  if (authority.grant(member)?.reader !== true) throw new Error('CELLD_INVITATION_MEMBER_FORBIDDEN')
  const grant = authority.grant(inviter)
  if (grant?.reader !== true || !grant.administrator) throw new Error('CELLD_INVITATION_ADMINISTRATOR_REQUIRED')
}

/** Seal a route for a member already admitted by the selected signed control record. */
export async function signCelldApplicationInvitation(input: {
  readonly authority: AuthorityBundle
  readonly memberPublicKey: string
  readonly endpoint: CelldPeerEndpoint
  readonly inviter: PeerIdentity
}): Promise<CelldApplicationInvitation> {
  const { memberPublicKey, inviter } = input
  const endpoint = structuredClone(input.endpoint)
  if (!key(memberPublicKey)) throw new Error('CELLD_INVITATION_MEMBER_INVALID')
  validateEndpoint(endpoint)
  const authority = await verifyAuthorityBundle(input.authority)
  if (authority.current === null) throw new Error('CELLD_INVITATION_GENERATION_REQUIRED')
  verifyMembers(authority, memberPublicKey, inviter.publicKey)
  const payload: InvitationPayload = {
    version: 1, memberPublicKey, inviterPublicKey: inviter.publicKey,
    generation: authority.current.id, endpoint, authority: authority.bundle,
  }
  const signature = await signDomain(DOMAINS.celldApplicationInvitation, encodePeerValue(payload), inviter.privateKey)
  return { payload, signature: bytesToHex(signature) }
}

/** Persist the admitted authority anchor before connecting to the authenticated peer. */
export async function acceptCelldApplicationInvitation(
  device: ApplicationDevice,
  invitation: CelldApplicationInvitation,
): Promise<AcceptedCelldApplicationInvitation> {
  const captured = structuredClone(invitation)
  if (!exactKeys(captured, ['payload', 'signature']) || typeof captured.signature !== 'string' ||
      !/^[0-9a-f]{128}$/u.test(captured.signature)) throw new Error('CELLD_INVITATION_INVALID')
  const { payload } = captured
  if (!exactKeys(payload, ['version', 'memberPublicKey', 'inviterPublicKey', 'generation', 'endpoint', 'authority']) ||
      payload.version !== 1 || !key(payload.inviterPublicKey) || !key(payload.generation)) {
    throw new Error('CELLD_INVITATION_INVALID')
  }
  if (payload.memberPublicKey !== device.identity.publicKey) throw new Error('CELLD_INVITATION_MEMBER_MISMATCH')
  validateEndpoint(payload.endpoint)
  const valid = await verifyDomain(
    DOMAINS.celldApplicationInvitation, encodePeerValue(payload), hexToBytes(captured.signature), hexToBytes(payload.inviterPublicKey),
  )
  if (!valid) throw new Error('CELLD_INVITATION_SIGNATURE_INVALID')
  const included = await verifyAuthorityBundle(payload.authority)
  if (included.current?.id !== payload.generation) throw new Error('CELLD_INVITATION_GENERATION_MISMATCH')
  verifyMembers(included, payload.memberPublicKey, payload.inviterPublicKey)
  const retained = await retainApplicationAuthority(device, included.bundle)
  verifyMembers(retained, payload.memberPublicKey, payload.inviterPublicKey)
  return {
    authority: retained.bundle,
    peer: { identity: payload.inviterPublicKey, route: payload.endpoint.nodeId },
    endpoint: payload.endpoint,
  }
}
