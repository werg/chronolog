import { bytesToHex, hexToBytes, sha256Sync, utf8 } from '@chronolog/canonical'
import { canonicalEventPayload, canonicalJson, verifyEd25519, type JsonValue } from '@chronolog/protocol'
import { hex, recordDigest, signRecord, verifyRecord, type Signed, type SigningIdentity } from './codec.js'

export interface AdmissionInclusion {
  readonly opId: string
  readonly authorTimestampMs: bigint
  readonly author: string
}

/**
 * Canonical checkpoint payload attested by external evidence (notary signature,
 * M-of-N quorum, optimistic proposal, Merkle/L1 anchor, or surgical descent anchor).
 */
export interface AdmissionCheckpointPayload {
  readonly logId: string
  readonly scopeId?: string
  readonly closedThroughMs: bigint
  readonly includedSetDigest: string
  readonly historyDigest: string
  readonly stateRoot: string
  /** CAS root of the scoped idempotency set `(visibility, author, operationId)` at the checkpoint. */
  readonly seenOpsRoot: string
  readonly inclusions: readonly AdmissionInclusion[]
}

/**
 * Protocol-agnostic external admission evidence handed to the log's state-defined
 * `$admission.admit(state, { ops, evidence, pinnedFrontier }, ctx)` function.
 *
 * Chronolog does not hardcode consensus or finality kinds in the protocol:
 * `kind` and `data` are interpreted deterministically by the log's own `$admission` module.
 */
export interface AdmissionEvidence {
  readonly kind: string
  readonly payload: AdmissionCheckpointPayload | JsonValue
  readonly data: JsonValue
}

export interface PinnedFrontier {
  readonly closedThroughMs: bigint
  readonly stateRoot: string
  readonly historyDigest: string
  readonly includedOpIds: readonly string[]
}

export interface AdmissionEquivocation {
  readonly signer: string
  readonly scopeId?: string
  readonly reason: string
  readonly detail?: string
}

export interface AdmissionDecision {
  readonly closedThroughMs: bigint | null
  readonly includedOpIds: ReadonlySet<string>
  readonly excludedOpIds: ReadonlySet<string>
  readonly latestCheckpoint: AdmissionEvidence | null
  readonly verifiedEvidence: readonly AdmissionEvidence[]
  readonly equivocations: readonly AdmissionEquivocation[]
}

export interface AdmissionEvaluatorInput {
  readonly logId: string
  readonly ops: readonly {
    readonly opId: string
    readonly author: string
    readonly authorTimestampMs: bigint
    readonly visibility: 'public' | 'encrypted'
  }[]
  readonly evidence: readonly AdmissionEvidence[]
  readonly pinnedFrontier?: PinnedFrontier | null
}

export interface RawAdmissionEvaluation {
  readonly closedThroughMs?: number | string | bigint | null
  readonly includedOpIds?: readonly string[]
  readonly excludedOpIds?: readonly string[]
  readonly verifiedEvidenceIndices?: readonly number[]
  readonly latestCheckpointIndex?: number | null
  readonly equivocations?: readonly AdmissionEquivocation[]
}

export type AdmissionEvaluator = (
  input: AdmissionEvaluatorInput,
) => RawAdmissionEvaluation | null | Promise<RawAdmissionEvaluation | null>

export function computeIncludedSetDigest(opIds: readonly string[]): string {
  const sorted = [...new Set(opIds)].sort()
  return bytesToHex(sha256Sync(utf8(JSON.stringify(sorted))))
}

/** Deterministic scope ID for a scheduled `$admission` history policy entry. */
export function computeAdmissionScopeId(
  logId: string,
  effectiveAfterMs: number | bigint,
  policy: JsonValue,
): string {
  hex(logId)
  return bytesToHex(sha256Sync(utf8(canonicalJson([
    'chronolog/admission-scope/v1',
    logId,
    typeof effectiveAfterMs === 'bigint' ? Number(effectiveAfterMs) : effectiveAfterMs,
    policy,
  ]))))
}

export function checkpointPayloadToJson(payload: AdmissionCheckpointPayload): JsonValue {
  return {
    logId: payload.logId,
    ...(payload.scopeId === undefined ? {} : { scopeId: payload.scopeId }),
    closedThroughMs: Number(payload.closedThroughMs),
    includedSetDigest: payload.includedSetDigest,
    historyDigest: payload.historyDigest,
    stateRoot: payload.stateRoot,
    seenOpsRoot: payload.seenOpsRoot,
    inclusions: payload.inclusions.map(i => ({
      opId: i.opId,
      authorTimestampMs: Number(i.authorTimestampMs),
      author: i.author,
    })),
  }
}

export function canonicalAdmissionCheckpointMessage(payload: AdmissionCheckpointPayload): string {
  hex(payload.logId)
  hex(payload.stateRoot)
  hex(payload.historyDigest)
  hex(payload.seenOpsRoot)
  return canonicalJson(['chronolog/admission-checkpoint/v1', checkpointPayloadToJson(payload)])
}

/** Sign an AdmissionCheckpointPayload with Ed25519 in the canonical admission-checkpoint format. */
export async function signAdmissionCheckpoint(
  payload: AdmissionCheckpointPayload,
  signer: SigningIdentity,
): Promise<{ readonly signer: string; readonly signature: string }> {
  const msg = utf8(canonicalAdmissionCheckpointMessage(payload))
  const sig = new Uint8Array(await crypto.subtle.sign('Ed25519', signer.privateKey, new Uint8Array(msg)))
  return { signer: signer.publicKey, signature: bytesToHex(sig) }
}

/** Sign an arbitrary canonical admission message (e.g. fraud challenge, Merkle anchor root). */
export async function signAdmissionMessage(
  domain: string,
  value: JsonValue,
  signer: SigningIdentity,
): Promise<{ readonly signer: string; readonly signature: string }> {
  const msg = utf8(canonicalJson([domain, value]))
  const sig = new Uint8Array(await crypto.subtle.sign('Ed25519', signer.privateKey, new Uint8Array(msg)))
  return { signer: signer.publicKey, signature: bytesToHex(sig) }
}

export async function evidenceDigest(evidence: AdmissionEvidence): Promise<string> {
  return recordDigest(evidence)
}

function toOptionalBigInt(val: number | string | bigint | null | undefined): bigint | null {
  if (val === null || val === undefined) return null
  if (typeof val === 'bigint') return val
  if (typeof val === 'number' && Number.isSafeInteger(val)) return BigInt(val)
  if (typeof val === 'string' && /^-?\d+$/u.test(val)) return BigInt(val)
  return null
}

/**
 * Evaluate history admission using the log's state-defined `$admission.admit(...)` evaluator,
 * while strictly enforcing any locally pinned checkpoint frontier (so a verified frontier can
 * never be unwound by backdated ops).
 */
export async function evaluateAdmission(options: {
  readonly logId: string
  readonly ops: readonly {
    readonly opId: string
    readonly author: string
    readonly authorTimestampMs: bigint
    readonly visibility: 'public' | 'encrypted'
  }[]
  /** Visible operation facts supplied to the policy on a private log. Closure still applies to all held ops. */
  readonly policyOps?: AdmissionEvaluatorInput['ops']
  readonly evidence: readonly AdmissionEvidence[]
  readonly pinnedFrontier?: PinnedFrontier | null
  readonly evaluator?: AdmissionEvaluator | null
}): Promise<AdmissionDecision> {
  hex(options.logId)
  const raw = options.evaluator
    ? await options.evaluator({
        logId: options.logId,
        ops: options.policyOps ?? options.ops,
        evidence: options.evidence,
        pinnedFrontier: options.pinnedFrontier ?? null,
      })
    : null

  let closedThroughMs = toOptionalBigInt(raw?.closedThroughMs)
  const includedOpIds = new Set<string>(raw?.includedOpIds ?? [])
  const excludedOpIds = new Set<string>(raw?.excludedOpIds ?? [])
  const verifiedEvidence: AdmissionEvidence[] = []
  const verifiedIndices = new Set<number>()
  if (Array.isArray(raw?.verifiedEvidenceIndices)) {
    for (const idx of raw.verifiedEvidenceIndices as readonly unknown[]) {
      if (typeof idx === 'number' && Number.isSafeInteger(idx) && idx >= 0 && idx < options.evidence.length && !verifiedIndices.has(idx)) {
        verifiedIndices.add(idx)
        verifiedEvidence.push(options.evidence[idx]!)
      }
    }
  }
  const latestCheckpoint =
    typeof raw?.latestCheckpointIndex === 'number' &&
    verifiedIndices.has(raw.latestCheckpointIndex)
      ? options.evidence[raw.latestCheckpointIndex]!
      : (verifiedEvidence.length > 0 ? verifiedEvidence[verifiedEvidence.length - 1]! : null)

  // Always honor a locally pinned frontier (surgical descent / non-rewinding checkpoint)
  if (options.pinnedFrontier !== undefined && options.pinnedFrontier !== null) {
    const pf = options.pinnedFrontier
    const pinnedIds = new Set(pf.includedOpIds)
    for (const op of options.ops) {
      if (op.authorTimestampMs <= pf.closedThroughMs && !pinnedIds.has(op.opId)) {
        includedOpIds.delete(op.opId)
        excludedOpIds.add(op.opId)
      }
    }
    for (const id of pinnedIds) {
      includedOpIds.add(id)
      excludedOpIds.delete(id)
    }
    if (closedThroughMs === null || pf.closedThroughMs > closedThroughMs) {
      closedThroughMs = pf.closedThroughMs
    }
  }

  // An excluded fact cannot also enter the finalized view.
  for (const id of excludedOpIds) includedOpIds.delete(id)

  // Enforce universal closed-time exclusion invariant: any op <= closedThroughMs not included is excluded
  if (closedThroughMs !== null) {
    for (const op of options.ops) {
      if (op.authorTimestampMs <= closedThroughMs && !includedOpIds.has(op.opId)) {
        excludedOpIds.add(op.opId)
      }
    }
  }

  return {
    closedThroughMs,
    includedOpIds,
    excludedOpIds,
    latestCheckpoint,
    verifiedEvidence,
    equivocations: raw?.equivocations ?? [],
  }
}

/** Domain tag of host attestations verified by `chronolog/admission` (`setMember` with `attestation`). */
export const HOST_ATTESTATION_DOMAIN = 'chronolog/host-attestation/v2'

/**
 * Fields every host attestation must carry: the attested device key, the log it may join, and an
 * expiry. `chronolog/admission` rejects an attestation whose `logId` is not the materializing log or
 * whose `expiresAtMs` is not after the admitting operation's `authorTimestampMs`.
 */
export interface HostAttestationPayload {
  readonly logId: string
  readonly publicKey: string
  readonly expiresAtMs: number
  readonly [field: string]: JsonValue
}

function hostAttestationMessage(payload: HostAttestationPayload): Uint8Array {
  hex(payload.logId)
  hex(payload.publicKey)
  if (!Number.isSafeInteger(payload.expiresAtMs) || payload.expiresAtMs <= 0) {
    throw Object.assign(new Error('HOST_ATTESTATION_EXPIRY_INVALID'), { code: 'HOST_ATTESTATION_EXPIRY_INVALID' })
  }
  return utf8(canonicalEventPayload([HOST_ATTESTATION_DOMAIN, payload]))
}

/** Sign a host attestation in the canonical `chronolog/host-attestation/v2` format verified by `chronolog/admission`. */
export async function signHostAttestationV2<T extends HostAttestationPayload>(
  payload: T,
  hostIdentity: SigningIdentity,
): Promise<{ readonly payload: T; readonly signature: string }> {
  const captured = structuredClone(payload)
  const msg = hostAttestationMessage(captured)
  const sig = new Uint8Array(await crypto.subtle.sign('Ed25519', hostIdentity.privateKey, Uint8Array.from(msg).buffer))
  return { payload: captured, signature: bytesToHex(sig) }
}

/**
 * Verify a host attestation exactly as `chronolog/admission` does: signature under `hostPublicKeyHex`,
 * `payload.logId === expected.logId`, and `payload.expiresAtMs > expected.atMs`.
 */
export async function verifyHostAttestationV2<T extends HostAttestationPayload>(
  attestation: { readonly payload: T; readonly signature: string },
  hostPublicKeyHex: string,
  expected: { readonly logId: string; readonly atMs: number },
): Promise<boolean> {
  if (!/^[0-9a-f]{64}$/u.test(hostPublicKeyHex) || !/^[0-9a-f]{128}$/u.test(attestation.signature)) return false
  const p = attestation.payload
  if (p === null || typeof p !== 'object' || p.logId !== expected.logId) return false
  if (!Number.isSafeInteger(p.expiresAtMs) || !(p.expiresAtMs > expected.atMs)) return false
  let msg: Uint8Array
  try { msg = hostAttestationMessage(p) } catch { return false }
  return verifyEd25519(hexToBytes(hostPublicKeyHex), msg, hexToBytes(attestation.signature))
}

/** Verify a signed CBOR record (helper re-exported for host/client consumers). */
export { signRecord, verifyRecord, recordDigest, type Signed }
