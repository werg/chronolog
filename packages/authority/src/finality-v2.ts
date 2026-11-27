import { bytesToHex, hexToBytes, sha256Sync, utf8 } from '@chronolog/canonical'
import { canonicalEventPayload, type EventPayload } from '@chronolog/protocol'
import { check, hex, recordDigest, signRecord, verifyRecord, type Signed, type SigningIdentity } from './codec.js'

export type FinalityPolicyV2 =
  | { readonly kind: 'none' }
  | { readonly kind: 'signed-frontier'; readonly signer: string }
  | { readonly kind: 'fixed-validator'; readonly validators: readonly string[]; readonly threshold: number }
  | { readonly kind: 'blockchain-anchor'; readonly chain: string; readonly anchorId: string }

export interface ScheduledFinalityEntry {
  readonly effectiveAfterMs: bigint
  readonly policy: FinalityPolicyV2
}

export interface FinalityInclusionV2 {
  readonly opId: string
  readonly authorTimestampMs: bigint
  readonly author: string
}

export interface FinalityCheckpointPayload {
  readonly logId: string
  readonly policyScopeId: string
  readonly closedThroughMs: bigint
  readonly includedSetDigest: string
  readonly historyDigest: string
  readonly stateRoot: string
  readonly inclusions: readonly FinalityInclusionV2[]
}

export type FinalityAttestation =
  | { readonly kind: 'signatures'; readonly signatures: readonly Signed<FinalityCheckpointPayload>[] }
  | { readonly kind: 'blockchain'; readonly blockHeight: number; readonly blockTimestampMs: bigint; readonly proofBytes: string }

export interface FinalityCheckpoint {
  readonly payload: FinalityCheckpointPayload
  readonly attestation: FinalityAttestation
}

export type BlockchainAnchorVerifier = (
  policy: Extract<FinalityPolicyV2, { readonly kind: 'blockchain-anchor' }>,
  checkpoint: FinalityCheckpoint,
) => boolean | Promise<boolean>

export interface EquivocationProof {
  readonly signer: string
  readonly policyScopeId: string
  readonly reason: 'conflicting_checkpoint_at_frontier' | 'dropped_prior_inclusion'
  readonly first: FinalityCheckpoint
  readonly second: FinalityCheckpoint
}

export interface VerifiedFinalityV2 {
  readonly closedThroughMs: bigint | null
  readonly includedOpIds: ReadonlySet<string>
  readonly excludedOpIds: ReadonlySet<string>
  readonly latestCheckpoint: FinalityCheckpoint | null
  readonly verifiedCheckpoints: readonly FinalityCheckpoint[]
  readonly equivocationProofs: readonly EquivocationProof[]
}

export async function policyScopeId(logId: string, entry: ScheduledFinalityEntry): Promise<string> {
  return recordDigest(['chronolog/finality-scope/v2', logId, entry.effectiveAfterMs, entry.policy])
}

export function computeIncludedSetDigest(opIds: readonly string[]): string {
  const sorted = [...new Set(opIds)].sort()
  return bytesToHex(sha256Sync(utf8(JSON.stringify(sorted))))
}

export async function signFinalityCheckpoint(
  payload: FinalityCheckpointPayload,
  signer: SigningIdentity,
): Promise<Signed<FinalityCheckpointPayload>> {
  return signRecord('chronolog/finality-checkpoint/v2', payload, signer)
}

export function parseFinalitySchedule(raw: unknown): readonly ScheduledFinalityEntry[] {
  if (raw === null || raw === undefined) return [{ effectiveAfterMs: -1n, policy: { kind: 'none' } }]
  check(typeof raw === 'object' && !Array.isArray(raw) && Array.isArray((raw as { schedule?: unknown }).schedule), 'FINALITY_SCHEDULE_INVALID')
  const list = (raw as { schedule: unknown[] }).schedule
  check(list.length > 0, 'FINALITY_SCHEDULE_EMPTY')
  const out: ScheduledFinalityEntry[] = []
  let prev = -2n
  for (const item of list) {
    check(item !== null && typeof item === 'object' && !Array.isArray(item), 'FINALITY_ENTRY_INVALID')
    const rec = item as { effectiveAfterMs: unknown; policy: unknown }
    const after = typeof rec.effectiveAfterMs === 'bigint'
      ? rec.effectiveAfterMs
      : typeof rec.effectiveAfterMs === 'number' && Number.isSafeInteger(rec.effectiveAfterMs)
        ? BigInt(rec.effectiveAfterMs)
        : (() => { throw new Error('FINALITY_ACTIVATION_INVALID') })()
    check(after > prev, 'FINALITY_ACTIVATION_NOT_MONOTONIC')
    prev = after
    out.push({ effectiveAfterMs: after, policy: rec.policy as FinalityPolicyV2 })
  }
  return out
}

async function verifyAttestationForPolicy(
  policy: FinalityPolicyV2,
  checkpoint: FinalityCheckpoint,
  blockchainVerifier?: BlockchainAnchorVerifier,
): Promise<boolean> {
  if (policy.kind === 'none') return false
  if (policy.kind === 'blockchain-anchor') {
    if (checkpoint.attestation.kind !== 'blockchain' || blockchainVerifier === undefined) return false
    return await blockchainVerifier(policy, checkpoint)
  }
  if (checkpoint.attestation.kind !== 'signatures') return false
  const allowed = policy.kind === 'signed-frontier' ? [policy.signer] : policy.validators
  const threshold = policy.kind === 'signed-frontier' ? 1 : policy.threshold
  const validSigners = new Set<string>()
  for (const sig of checkpoint.attestation.signatures) {
    if (!allowed.includes(sig.signer)) continue
    try {
      await verifyRecord('chronolog/finality-checkpoint/v2', sig, sig.signer)
      if (await recordDigest(sig.payload) === await recordDigest(checkpoint.payload)) {
        validSigners.add(sig.signer)
      }
    } catch { /* invalid sig ignored */ }
  }
  return validSigners.size >= threshold
}

/**
 * Verify finality checkpoints against the chain-governed $finality schedule.
 * - Enforces P0 -> P1 handoff at effectiveAfterMs = T1:
 *   * If P0 is a finalizing policy, P0 must have closed through >= T1 before P1 checkpoints are accepted.
 *   * If P0 is 'none', P1 itself attests its bootstrap closure at >= T1 as its first sealed frontier.
 * - Computes admitted/excluded opIds (proposals with authorTimestampMs <= closedThroughMs not in includedOpIds are excluded).
 */
export async function verifyFinalityV2(options: {
  readonly logId: string
  readonly schedule: readonly ScheduledFinalityEntry[]
  readonly checkpoints: readonly FinalityCheckpoint[]
  readonly knownOps?: readonly { readonly opId: string; readonly authorTimestampMs: bigint }[]
  readonly blockchainVerifier?: BlockchainAnchorVerifier
}): Promise<VerifiedFinalityV2> {
  hex(options.logId)
  const scopeEntries = await Promise.all(
    options.schedule.map(async (entry, index) => ({
      index,
      entry,
      scopeId: await policyScopeId(options.logId, entry),
    })),
  )
  const byScope = new Map(scopeEntries.map(s => [s.scopeId, s]))

  // Sort checkpoints chronologically by closedThroughMs
  const sorted = [...options.checkpoints].sort((a, b) =>
    a.payload.closedThroughMs < b.payload.closedThroughMs ? -1 : a.payload.closedThroughMs > b.payload.closedThroughMs ? 1 : 0,
  )

  const verifiedCheckpoints: FinalityCheckpoint[] = []
  const includedOpIds = new Set<string>()
  let highestClosed: bigint | null = null
  const closedByScopeIndex = new Map<number, bigint>()

  for (const cp of sorted) {
    const p = cp.payload
    if (p.logId !== options.logId) continue
    const scope = byScope.get(p.policyScopeId)
    if (scope === undefined) continue
    if (scope.entry.policy.kind === 'none') continue
    if (p.closedThroughMs < scope.entry.effectiveAfterMs) continue

    // Enforce handoff from previous policy P_{i-1} -> P_i
    if (scope.index > 0) {
      const prev = scopeEntries[scope.index - 1]!
      if (prev.entry.policy.kind !== 'none') {
        const prevClosed = closedByScopeIndex.get(prev.index)
        if (prevClosed === undefined || prevClosed < scope.entry.effectiveAfterMs) {
          // Outgoing finalizing policy has not yet sealed the handoff timestamp T1!
          continue
        }
      }
      // When prev.entry.policy.kind === 'none', P_i itself attests its bootstrap frontier at >= T1.
    }

    const ok = await verifyAttestationForPolicy(scope.entry.policy, cp, options.blockchainVerifier)
    if (!ok) continue

    for (const inc of p.inclusions) {
      includedOpIds.add(inc.opId)
    }
    const prevScopeClosed = closedByScopeIndex.get(scope.index)
    if (prevScopeClosed === undefined || p.closedThroughMs > prevScopeClosed) {
      closedByScopeIndex.set(scope.index, p.closedThroughMs)
    }
    if (highestClosed === null || p.closedThroughMs > highestClosed) {
      highestClosed = p.closedThroughMs
    }
    verifiedCheckpoints.push(cp)
  }

  const excludedOpIds = new Set<string>()
  if (highestClosed !== null && options.knownOps !== undefined) {
    for (const op of options.knownOps) {
      if (op.authorTimestampMs <= highestClosed && !includedOpIds.has(op.opId)) {
        excludedOpIds.add(op.opId)
      }
    }
  }

  // Detect cryptographic notary/validator equivocation across verified checkpoints
  const equivocationProofs: EquivocationProof[] = []
  const bySignerScope = new Map<string, FinalityCheckpoint[]>()
  for (const cp of verifiedCheckpoints) {
    if (cp.attestation.kind !== 'signatures') continue
    for (const sig of cp.attestation.signatures) {
      const key = `${sig.signer}:${cp.payload.policyScopeId}`
      let list = bySignerScope.get(key)
      if (list === undefined) { list = []; bySignerScope.set(key, list) }
      list.push(cp)
    }
  }
  for (const [key, list] of bySignerScope) {
    const sep = key.indexOf(':')
    const signer = key.slice(0, sep)
    const scopeId = key.slice(sep + 1)
    for (let i = 0; i < list.length; i++) {
      const a = list[i]!
      const aOps = new Set(a.payload.inclusions.map(x => x.opId))
      for (let j = i + 1; j < list.length; j++) {
        const b = list[j]!
        if (a.payload.closedThroughMs === b.payload.closedThroughMs) {
          if (
            a.payload.includedSetDigest !== b.payload.includedSetDigest ||
            a.payload.stateRoot !== b.payload.stateRoot ||
            a.payload.historyDigest !== b.payload.historyDigest
          ) {
            equivocationProofs.push({
              signer,
              policyScopeId: scopeId,
              reason: 'conflicting_checkpoint_at_frontier',
              first: a,
              second: b,
            })
          }
        } else if (b.payload.closedThroughMs > a.payload.closedThroughMs && aOps.size > 0 && b.payload.inclusions.length > 0) {
          const bOps = new Set(b.payload.inclusions.map(x => x.opId))
          const bMinTs = b.payload.inclusions.reduce((min, x) => (x.authorTimestampMs < min ? x.authorTimestampMs : min), b.payload.inclusions[0]!.authorTimestampMs)
          // Only flag dropped inclusion when b overlaps a's timestamp range (full cumulative checkpoint)
          if (bMinTs <= a.payload.closedThroughMs) {
            let dropped = false
            for (const opId of aOps) {
              if (!bOps.has(opId)) { dropped = true; break }
            }
            if (dropped) {
              equivocationProofs.push({
                signer,
                policyScopeId: scopeId,
                reason: 'dropped_prior_inclusion',
                first: a,
                second: b,
              })
            }
          }
        }
      }
    }
  }

  return {
    closedThroughMs: highestClosed,
    includedOpIds,
    excludedOpIds,
    latestCheckpoint: verifiedCheckpoints.at(-1) ?? null,
    verifiedCheckpoints,
    equivocationProofs,
  }
}

/** Pure host-attestation helper matching chronolog/permissions's Ed25519 verification format. */
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
