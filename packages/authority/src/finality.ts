import { check, equalRecord, hex, recordDigest, signRecord, verifyRecord, type Signed, type SigningIdentity } from './codec.js'
import { writerAuthorizedAt, finalizerAuthorizedAt, type AppDescriptor, type FinalityPolicy, type AuthorityProvider, type AdmissionScope } from './control.js'
const isArray = (value: unknown): boolean => Array.isArray(value)
export interface Inclusion { readonly proposalId: string; readonly authorTimestampMs: bigint; readonly membershipId: string; readonly author: string }
export interface FinalityStatement {
  readonly applicationId: string
  readonly policyDigest: string
  /** Complete authenticated membership head known to this closure signer. */
  readonly authorityHead: string
  readonly scope: string
  readonly sequence: number
  readonly previous: string | null
  /** Newly first-included proposals. All historical first inclusions remain effective. */
  readonly inclusions: readonly Inclusion[]
  readonly closedThroughMs: bigint
  readonly blockers: readonly Inclusion[]
}
export interface FinalityProof { readonly statement: FinalityStatement; readonly signatures: readonly Signed<FinalityStatement>[] }
export interface VerifiedFinality {
  readonly closedThroughMs: bigint | null
  /** First inclusion is valid in EVERY applicable policy and historical membership scope. */
  readonly included: ReadonlyMap<string, Inclusion>
  readonly excludedProposalIds: ReadonlySet<string>
  readonly proofs: readonly FinalityProof[]
  readonly pendingDependencies?: readonly string[]
  readonly certifiedProofs?: readonly FinalityProof[]
}
export async function finalityPolicyDigest(policy: FinalityPolicy): Promise<string> { return recordDigest(['finality-policy', policy]) }
export async function signFinalityStatement(statement: FinalityStatement, signer: SigningIdentity): Promise<Signed<FinalityStatement>> { return signRecord('finality', statement, signer) }
export async function finalityAdmissionScopes(authority: AuthorityProvider): Promise<readonly AdmissionScope[]> {
  const policy = authority.descriptor.finalityPolicy
  if (policy.kind === 'none') return []
  const scopes = new Map(policy.scopes.map(scope => [scope.id, scope]))
  for (const membership of authority.bundle().memberships) { const id = await recordDigest(membership); check(!scopes.has(id), 'FINALITY_SCOPE_COLLISION'); scopes.set(id, { id, authorTimeAfterMs: membership.payload.authorTimeAfterMs }) }
  return [...scopes.values()]
}
/** Certificates are evidence sets keyed by statement identity, not by signature array/envelope bytes. */
export async function mergeFinalityProofs(...histories: readonly (readonly FinalityProof[])[]): Promise<readonly FinalityProof[]> {
  const statements = new Map<string, { statement: FinalityStatement; signatures: Map<string, Signed<FinalityStatement>> }>()
  for (const history of histories) for (const input of history) {
    const proof = structuredClone(input), id = await recordDigest(proof.statement)
    check(proof.signatures.length <= 4096, 'FINALITY_SIGNATURE_LIMIT')
    let entry = statements.get(id)
    if (entry === undefined) { entry = { statement: proof.statement, signatures: new Map() }; statements.set(id, entry) }
    for (const signature of proof.signatures) {
      check(equalRecord(signature.payload, proof.statement), 'FINALITY_SIGNATURE_SCOPE'); await verifyRecord('finality', signature)
      const prior = entry.signatures.get(signature.signer)
      if (prior === undefined || signature.signature < prior.signature) entry.signatures.set(signature.signer, signature)
    }
  }
  check(statements.size <= 65536, 'FINALITY_PROOF_LIMIT')
  return [...statements.values()].map(entry => ({ statement: entry.statement, signatures: [...entry.signatures.values()].sort((a, b) => a.signer.localeCompare(b.signer)) })).sort((a, b) => a.statement.scope.localeCompare(b.statement.scope) || a.statement.sequence - b.statement.sequence)
}
/** Proofs certify historical first inclusion/closure; neither this verifier nor its provider assigns operation order.
 * knownProposals contains already authenticated authored facts, not claims supplied by an untrusted UI.
 */
export async function verifyFinalityProofs(descriptor: AppDescriptor, input: readonly FinalityProof[], authority?: AuthorityProvider, knownProposals: readonly Inclusion[] = []): Promise<VerifiedFinality> {
  const policy = descriptor.finalityPolicy
  if (policy.kind === 'none') { check(input.length === 0, 'FINALITY_UNSUPPORTED'); return { closedThroughMs: null, included: new Map(), excludedProposalIds: new Set(), proofs: [] } }
  check(authority !== undefined, 'FINALITY_AUTHORITY_REQUIRED')
  check(equalRecord(descriptor, authority.descriptor), 'FINALITY_AUTHORITY_SCOPE_MISMATCH')
  const proofs = await mergeFinalityProofs(input), scopes = await finalityAdmissionScopes(authority), policyDigest = await finalityPolicyDigest(policy)
  const allowed = policy.kind === 'signed-frontier' ? [policy.signer] : policy.validators, threshold = policy.kind === 'signed-frontier' ? 1 : policy.threshold
  const heads = new Map<string, { sequence: number; id: string; closed: bigint }>(), first = new Map<string, Map<string, { inclusion: Inclusion; late: boolean }>>()
  const candidates = new Map<string, Inclusion>(), dependencies = new Set<string>(), verifiedProofs: FinalityProof[] = []
  const candidate = (value: Inclusion): void => {
    hex(value.proposalId); hex(value.membershipId); hex(value.author); check(typeof value.authorTimestampMs === 'bigint' && value.authorTimestampMs >= 0n && value.authorTimestampMs <= (1n << 63n) - 1n, 'FINALITY_INCLUSION_INVALID')
    const prior = candidates.get(value.proposalId); check(prior === undefined || prior.authorTimestampMs === value.authorTimestampMs && prior.membershipId === value.membershipId && prior.author === value.author, 'FINALITY_INCLUSION_CONFLICT'); candidates.set(value.proposalId, value)
  }
  for (const value of knownProposals) candidate(value)
  for (const proof of proofs) {
    const statement = proof.statement, scope = scopes.find(item => item.id === statement.scope), head = heads.get(statement.scope)
    hex(statement.scope); hex(statement.authorityHead)
    check(statement.applicationId === descriptor.applicationId && statement.policyDigest === policyDigest, 'FINALITY_SCOPE_MISMATCH')
    check(Number.isSafeInteger(statement.sequence) && statement.sequence >= 0 && typeof statement.closedThroughMs === 'bigint' && statement.closedThroughMs >= -1n && statement.closedThroughMs <= (1n << 63n) - 1n && isArray(statement.inclusions) && isArray(statement.blockers) && statement.inclusions.length <= 65536 && statement.blockers.length <= 65536, 'FINALITY_STATEMENT_INVALID')
    check(proof.signatures.length <= allowed.length, 'FINALITY_SIGNATURE_LIMIT')
    for (const signature of proof.signatures) check(allowed.includes(signature.signer), 'FINALITY_SIGNATURE_SCOPE')
    const headMembership = authority.membership(statement.authorityHead)
    if (headMembership === null) { dependencies.add(`authority/${statement.authorityHead}`); continue }
    // The descriptor fixes eligible keys/threshold; membership grants do not silently change that quorum.
    // Revoked keys cannot close a later author-time range by pretending to use an old authority head.
    const eligible = proof.signatures.filter(signature => finalizerAuthorizedAt(authority, signature.signer, statement.authorityHead, statement.closedThroughMs) === true)
    if (eligible.length < threshold) { dependencies.add(`quorum/${await recordDigest(statement)}`); continue }
    check(scope !== undefined, 'FINALITY_SCOPE_MISMATCH')
    { const membership = authority.membership(statement.scope); check(membership === null || membership.revision <= headMembership.revision, 'FINALITY_SCOPE_NOT_ACTIVE') }
    if (statement.sequence > (head?.sequence ?? -1) + 1) { dependencies.add(`history/${statement.scope}/${(head?.sequence ?? -1) + 1}`); continue }
    check(statement.sequence === (head?.sequence ?? -1) + 1 && statement.previous === (head?.id ?? null), 'FINALITY_HISTORY_FORK')
    check(statement.closedThroughMs >= (head?.closed ?? scope.authorTimeAfterMs), 'FINALITY_CLOSURE_INVALID')
    for (const blocker of statement.blockers) { candidate(blocker); check(statement.closedThroughMs < blocker.authorTimestampMs, 'FINALITY_BLOCKER_NOT_RESPECTED') }
    const scopedFirst = first.get(statement.scope) ?? new Map<string, { inclusion: Inclusion; late: boolean }>(); first.set(statement.scope, scopedFirst)
    for (const inclusion of statement.inclusions) {
      candidate(inclusion); check(inclusion.authorTimestampMs > scope.authorTimeAfterMs, 'FINALITY_INCLUSION_INVALID')
      {
        const membership = authority.membership(inclusion.membershipId)
        check(membership !== null && membership.revision <= headMembership.revision && writerAuthorizedAt(authority, inclusion.author, inclusion.membershipId, inclusion.authorTimestampMs, headMembership.revision) === true, 'FINALITY_INCLUSION_SCOPE_INVALID')
        check(!authority.hasMembership(statement.scope) || statement.scope === inclusion.membershipId, 'FINALITY_INCLUSION_SCOPE_INVALID')
      }
      check(!scopedFirst.has(inclusion.proposalId), 'FINALITY_FIRST_INCLUSION_REPEATED')
      scopedFirst.set(inclusion.proposalId, { inclusion, late: inclusion.authorTimestampMs <= (head?.closed ?? scope.authorTimeAfterMs) })
    }
    heads.set(statement.scope, { sequence: statement.sequence, id: await recordDigest(statement), closed: statement.closedThroughMs }); verifiedProofs.push(proof)
  }
  const memberships = authority.bundle().memberships, membershipIds = await Promise.all(memberships.map(membership => recordDigest(membership)))
  // A signed membership activation cannot reopen author time already sealed under an earlier complete authority head.
  for (let index = 1; index < memberships.length; index++) {
    const priorScopes = [...policy.scopes, ...memberships.slice(0, index).map((membership, position) => ({ id: membershipIds[position]!, authorTimeAfterMs: membership.payload.authorTimeAfterMs }))]
    let sealed = (1n << 63n) - 1n
    for (const scope of priorScopes) { const prior = verifiedProofs.filter(proof => proof.statement.scope === scope.id && (authority.membership(proof.statement.authorityHead)?.revision ?? Infinity) < index).at(-1)?.statement, cutoff = prior?.closedThroughMs ?? scope.authorTimeAfterMs; if (cutoff < sealed) sealed = cutoff }
    check(memberships[index]!.payload.authorTimeAfterMs >= sealed, 'FINALITY_MEMBERSHIP_BEHIND_SEAL')
  }
  const included = new Map<string, Inclusion>(), excluded = new Set<string>()
  for (const value of candidates.values()) {
    const applicable = policy.scopes.filter(scope => value.authorTimestampMs > scope.authorTimeAfterMs).map(scope => scope.id)
    {
      if (writerAuthorizedAt(authority, value.author, value.membershipId, value.authorTimestampMs) === false) excluded.add(value.proposalId)
      applicable.push(value.membershipId)
    }
    let complete = applicable.length > 0
    for (const id of applicable) {
      const admission = first.get(id)?.get(value.proposalId), closed = heads.get(id)?.closed
      if (admission?.late === true || admission === undefined && closed !== undefined && value.authorTimestampMs <= closed) excluded.add(value.proposalId)
      if (admission === undefined || admission.late) complete = false
    }
    if (complete && !excluded.has(value.proposalId)) included.set(value.proposalId, value)
  }
  let closedThroughMs: bigint | null = null
  for (const scope of scopes) { const cutoff = heads.get(scope.id)?.closed ?? scope.authorTimeAfterMs; if (closedThroughMs === null || cutoff < closedThroughMs) closedThroughMs = cutoff }
  if (closedThroughMs !== null && closedThroughMs < 0n) closedThroughMs = null
  return { closedThroughMs, included, excludedProposalIds: excluded, proofs, certifiedProofs: verifiedProofs, pendingDependencies: [...dependencies].sort() }
}
export interface FinalityProvider { read(): Promise<readonly FinalityProof[]>; publish(proof: FinalityProof): Promise<void> }
