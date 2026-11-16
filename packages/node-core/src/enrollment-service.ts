import type { CapabilitySnapshot } from '@chronolog/capabilities'
import {
  decodeSignedEnrollmentApproval, decodeSignedEnrollmentRequest,
  encodeSignedEnrollmentApproval, encodeSignedEnrollmentRequest,
  enrollmentProgress, loadEnrollmentApproval, loadEnrollmentRequest,
  prepareEnrollmentRequest, saveEnrollmentApproval,
  type EnrollmentDescriptor, type EnrollmentFinalTarget,
  type EnrollmentIssuer, type EnrollmentRole,
} from './enrollment.js'
import type { DurableOperationStore } from './operations.js'
import type { GovernanceControlPlane } from './governance.js'
import { base64UrlToBytes, bytesToBase64Url as base64url, equalBytes, type Ed25519KeyPair } from '@chronolog/protocol'

export interface EnrollmentServiceOptions {
  readonly descriptor: EnrollmentDescriptor
  readonly store: DurableOperationStore
  /** The running replica's existing durable signer and feed, never a new hidden identity. */
  readonly identity: Ed25519KeyPair
  readonly readerPublicKey: Uint8Array
  readonly transportAuthor: string
  readonly governance: GovernanceControlPlane
  readonly activeMembership: () => CapabilitySnapshot
  readonly issuer?: EnrollmentIssuer
  readonly connected: () => boolean | Promise<boolean>
  readonly executionManifestDigest: Uint8Array
  readonly isFinalTargetApplied: (target: EnrollmentFinalTarget) => boolean | Promise<boolean>
}

export function createEnrollmentService(options: EnrollmentServiceOptions) {
  return {
    async createRequest(request: { readonly requestId: string; readonly roles: readonly EnrollmentRole[] }) {
      const signed = await prepareEnrollmentRequest({
        descriptor: options.descriptor, store: options.store, requestId: request.requestId,
        requestedRoles: request.roles, identity: options.identity,
        readerPublicKey: options.readerPublicKey, transportAuthor: options.transportAuthor,
      })
      return { signedRequest: base64url(encodeSignedEnrollmentRequest(signed)) }
    },

    async approveRequest(request: {
      readonly requestId: string
      readonly signedRequest: string
      readonly roles: readonly EnrollmentRole[]
      readonly grantFullHistory: boolean
    }) {
      if (options.issuer === undefined) throw new Error('ENROLLMENT_ISSUER_UNAVAILABLE')
      const approval = await options.issuer.approve(decodeSignedEnrollmentRequest(decodeBase64url(request.signedRequest)), {
        operationId: request.requestId, roles: request.roles, grantFullHistory: request.grantFullHistory,
      })
      return { signedApproval: base64url(encodeSignedEnrollmentApproval(approval)) }
    },

    async getStatus(request: { readonly requestId: string; readonly signedApproval?: string }) {
      const signed = await loadEnrollmentRequest(options.store, options.descriptor.history.groupId, request.requestId)
      if (signed === null) throw new Error('ENROLLMENT_REQUEST_NOT_FOUND')
      if (!equalBytes(signed.request.signingPublicKey, options.identity.publicKeyBytes) ||
          !equalBytes(signed.request.readerPublicKey, options.readerPublicKey) ||
          signed.request.transportAuthor !== options.transportAuthor) throw new Error('ENROLLMENT_REQUEST_NOT_LOCAL')
      if (request.signedApproval !== undefined) {
        await saveEnrollmentApproval({ descriptor: options.descriptor, request: signed, store: options.store,
          approval: decodeSignedEnrollmentApproval(decodeBase64url(request.signedApproval)) })
      }
      const progress = await enrollmentProgress({
        descriptor: options.descriptor, request: signed,
        approval: await loadEnrollmentApproval(options.store, signed.request),
        activeMembership: options.activeMembership(), connected: await options.connected(),
        availableEpochs: options.governance.cipherRing.epochs(),
        executionManifestDigest: options.executionManifestDigest,
        isFinalTargetApplied: options.isFinalTargetApplied,
      })
      return { requestId: request.requestId, state: progress.state,
        missingEpochs: progress.missingEpochs.map(String), roles: progress.roles }
    },
  }
}

function decodeBase64url(value: string): Uint8Array {
  if (!/^[A-Za-z0-9_-]+$/u.test(value) || value.length > 1_000_000) throw new Error('ENROLLMENT_BYTES_INVALID')
  return base64UrlToBytes(value)
}
