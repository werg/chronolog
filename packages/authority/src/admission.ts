import { bytesToHex, hexToBytes, sha256Sync, utf8 } from '@chronolog/canonical'
import { canonicalEventPayload, canonicalJson, type EventPayload, type JsonValue } from '@chronolog/protocol'
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
    inclusions: payload.inclusions.map(i => ({
      opId: i.opId,
      authorTimestampMs: Number(i.authorTimestampMs),
      author: i.author,
    })),
  }
}

export function canonicalAdmissionCheckpointMessage(payload: AdmissionCheckpointPayload): string {
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
  readonly evidence: readonly AdmissionEvidence[]
  readonly pinnedFrontier?: PinnedFrontier | null
  readonly evaluator?: AdmissionEvaluator | null
}): Promise<AdmissionDecision> {
  hex(options.logId)
  const raw = options.evaluator
    ? await options.evaluator({
        logId: options.logId,
        ops: options.ops,
        evidence: options.evidence,
        pinnedFrontier: options.pinnedFrontier ?? null,
      })
    : null

  let closedThroughMs = toOptionalBigInt(raw?.closedThroughMs)
  const includedOpIds = new Set<string>(raw?.includedOpIds ?? [])
  const excludedOpIds = new Set<string>(raw?.excludedOpIds ?? [])
  const verifiedEvidence: AdmissionEvidence[] = []
  if (Array.isArray(raw?.verifiedEvidenceIndices)) {
    for (const idx of raw.verifiedEvidenceIndices) {
      if (typeof idx === 'number' && Number.isSafeInteger(idx) && idx >= 0 && idx < options.evidence.length) {
        verifiedEvidence.push(options.evidence[idx]!)
      }
    }
  }
  const latestCheckpoint =
    typeof raw?.latestCheckpointIndex === 'number' &&
    raw.latestCheckpointIndex >= 0 &&
    raw.latestCheckpointIndex < options.evidence.length
      ? options.evidence[raw.latestCheckpointIndex]!
      : (verifiedEvidence.length > 0 ? verifiedEvidence[verifiedEvidence.length - 1]! : null)

  // Always honor a locally pinned frontier (surgical descent / non-rewinding checkpoint)
  if (options.pinnedFrontier !== undefined && options.pinnedFrontier !== null) {
    const pf = options.pinnedFrontier
    for (const id of pf.includedOpIds) includedOpIds.add(id)
    if (closedThroughMs === null || pf.closedThroughMs > closedThroughMs) {
      closedThroughMs = pf.closedThroughMs
    }
  }

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

/** Pure host-attestation helper matching `chronolog/admission`'s Ed25519 verification format. */
export async function signHostAttestationV2<T extends EventPayload>(
  payload: T,
  hostIdentity: SigningIdentity,
): Promise<{ readonly payload: T; readonly signature: string }> {
  const msg = utf8(canonicalEventPayload(['chronolog/host-attestation/v1', payload]))
  const sig = new Uint8Array(await crypto.subtle.sign('Ed25519', hostIdentity.privateKey, Uint8Array.from(msg).buffer))
  return { payload: structuredClone(payload), signature: bytesToHex(sig) }
}

export async function verifyHostAttestationV2<T extends EventPayload>(
  attestation: { readonly payload: T; readonly signature: string },
  hostPublicKeyHex: string,
): Promise<boolean> {
  if (!/^[0-9a-f]{64}$/u.test(hostPublicKeyHex) || !/^[0-9a-f]{128}$/u.test(attestation.signature)) return false
  const key = await crypto.subtle.importKey('raw', Uint8Array.from(hexToBytes(hostPublicKeyHex)).buffer, 'Ed25519', false, ['verify'])
  const msg = utf8(canonicalEventPayload(['chronolog/host-attestation/v1', attestation.payload]))
  return crypto.subtle.verify('Ed25519', key, Uint8Array.from(hexToBytes(attestation.signature)).buffer, Uint8Array.from(msg).buffer)
}

/** Verify a signed CBOR record (helper re-exported for host/client consumers). */
export { signRecord, verifyRecord, recordDigest, type Signed }
