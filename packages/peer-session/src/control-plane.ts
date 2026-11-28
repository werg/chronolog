import { bytesToHex } from '@chronolog/canonical'
import {
  evaluateAdmission,
  type AdmissionDecision,
  type AdmissionEvidence,
  type PinnedFrontier,
} from '@chronolog/authority'
import type { KernelMaterializeResult, KernelOperationInput, TopicKernel } from '@chronolog/materializer'

/** Operation facts used to apply the admission decision to a replica's local history. */
export interface AdmissionOpRef {
  readonly opId: string
  readonly author: string
  readonly authorTimestampMs: bigint
  readonly visibility: 'public' | 'encrypted'
}

export function admissionOpRef(input: KernelOperationInput): AdmissionOpRef {
  return {
    opId: bytesToHex(input.opId),
    author: bytesToHex(input.core.author),
    authorTimestampMs: input.core.authorTimestampMs,
    visibility: input.core.visibility,
  }
}

export interface MaterializeControlOptions {
  readonly logId: string
  /** Kernel that folds EVERY public op; its `$admission` state judges history (`admit`). */
  readonly probe: TopicKernel
  readonly publicOps: readonly KernelOperationInput[]
  /** Locally held ops to which the public decision applies. Defaults to `publicOps`. */
  readonly admissionOps?: readonly AdmissionOpRef[]
  readonly evidence: readonly AdmissionEvidence[]
  readonly pinnedFrontier: PinnedFrontier | null
  /**
   * Where the admitted control state lives when some public op is excluded:
   * - a function returning a kernel: that kernel folds the admitted public ops (full replicas keep
   *   a persistent one so the probe never rewinds back and forth),
   * - `'probe'` (default): the probe itself is refolded without the excluded ops (one-shot hosts),
   * - `'caller'`: the caller folds the admitted ops itself (a public-log replica's main kernel).
   */
  readonly admitted?: (() => TopicKernel) | 'probe' | 'caller'
}

export interface ControlPlaneResult {
  readonly admission: AdmissionDecision
  /** Kernel holding the admitted control state (the probe when nothing public was excluded). */
  readonly control: TopicKernel
  readonly result: KernelMaterializeResult
  /** Public ops admitted into the local view (all of `publicOps` minus `admission.excludedOpIds`). */
  readonly admittedPublicOps: readonly KernelOperationInput[]
}

/**
 * The ONE control-plane derivation shared by full replicas (`ApplicationSession`), blind hosts
 * (`replayBlindHostControl`) and hosted runners: fold every public op into the probe, evaluate the
 * log's `$admission.admit` over the ops, evidence and pinned frontier, and derive the control state
 * from the admitted public ops only. Both sides therefore agree on `$*` state even when evidence
 * excludes operations.
 */
export async function materializeControl(options: MaterializeControlOptions): Promise<ControlPlaneResult> {
  const probeResult = await options.probe.materialize(options.publicOps)
  const publicRefs = options.publicOps.map(admissionOpRef)
  const admission = await evaluateAdmission({
    logId: options.logId,
    ops: options.admissionOps ?? publicRefs,
    policyOps: publicRefs,
    evidence: options.evidence,
    pinnedFrontier: options.pinnedFrontier,
    evaluator: options.probe.createAdmissionEvaluator(),
  })
  const admittedPublicOps = admission.excludedOpIds.size === 0
    ? options.publicOps
    : options.publicOps.filter(op => !admission.excludedOpIds.has(bytesToHex(op.opId)))
  if (admittedPublicOps.length === options.publicOps.length || options.admitted === 'caller') {
    return { admission, control: options.probe, result: probeResult, admittedPublicOps }
  }
  const control = typeof options.admitted === 'function' ? options.admitted() : options.probe
  const result = await control.materialize(admittedPublicOps)
  return { admission, control, result, admittedPublicOps }
}

/** Inputs of the finalized view: only ops the admission decision includes (empty when nothing is closed). */
export function finalizedInputs<T extends KernelOperationInput>(inputs: Iterable<T>, admission: AdmissionDecision): T[] {
  const out: T[] = []
  if (admission.closedThroughMs === null) return out
  for (const input of inputs) if (admission.includedOpIds.has(bytesToHex(input.opId))) out.push(input)
  return out
}
